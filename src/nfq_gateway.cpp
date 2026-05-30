#include "wiremark/nfq_gateway.hpp"

#include "wiremark/compact.hpp"
#include "wiremark/crypto.hpp"
#include "wiremark/protocol.hpp"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <sys/select.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace wiremark {

namespace {

volatile std::sig_atomic_t g_nfq_stop = 0;
constexpr std::uint32_t kFragMagic = 0x574d4631;  // WMF1
constexpr std::size_t kFragHeaderSize = 20;

void on_nfq_signal(int) {
  g_nfq_stop = 1;
}

struct FragmentBuffer {
  std::uint64_t first_ms{0};
  std::uint16_t count{0};
  std::size_t received{0};
  std::size_t total_len{0};
  std::vector<Bytes> parts;
};

struct NfqContext {
  UdpSocket udp;
  Logger& logger;
  KeyMaterial keys;
  std::uint16_t wrapper_port{0};
  std::uint16_t wrapper_mtu{1200};
  bool fail_closed{true};
  PacketPolicy invalid_policy{PacketPolicy::Drop};
  PacketPolicy replay_policy{PacketPolicy::Drop};
  std::filesystem::path quarantine_dir;
  std::string device_id;
  std::array<std::uint8_t, 16> session_id{};
  std::uint64_t round_start{now_ms()};
  std::uint64_t data_seq{1};
  std::uint64_t frame_seq{1};
  std::map<std::string, FragmentBuffer> fragments;
  std::set<std::pair<std::array<std::uint8_t, 16>, std::uint64_t>> seen_sequences;
  std::set<std::array<std::uint8_t, 32>> seen_hashes;

  NfqContext(const NfqGatewayConfig& cfg, Logger& l)
      : udp(cfg.listen, cfg.peer),
        logger(l),
        keys(derive_keys(read_key_file(cfg.key_file), "nfq-v1")),
        wrapper_port(cfg.listen.port),
        wrapper_mtu(cfg.wrapper_mtu),
        fail_closed(cfg.fail_closed),
        invalid_policy(cfg.invalid_policy),
        replay_policy(cfg.replay_policy),
        quarantine_dir(cfg.quarantine_dir),
        device_id(cfg.device_id) {
    const auto sid = random_bytes(session_id.size());
    std::copy(sid.begin(), sid.end(), session_id.begin());
  }
};

std::array<std::uint8_t, 12> random_nonce12() {
  std::array<std::uint8_t, 12> out{};
  const auto r = random_bytes(out.size());
  std::copy(r.begin(), r.end(), out.begin());
  return out;
}

void put_u16_at(Bytes& data, std::size_t pos, std::uint16_t v) {
  data[pos] = static_cast<std::uint8_t>(v >> 8);
  data[pos + 1] = static_cast<std::uint8_t>(v);
}

std::uint32_t checksum_sum(const std::uint8_t* data, std::size_t len, std::uint32_t sum = 0) {
  std::size_t i = 0;
  while (i + 1 < len) {
    sum += (static_cast<std::uint16_t>(data[i]) << 8) | data[i + 1];
    i += 2;
  }
  if (i < len) sum += static_cast<std::uint16_t>(data[i]) << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return sum;
}

std::uint16_t checksum_finish(std::uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<std::uint16_t>(~sum);
}

void finalize_ipv4_checksums(Bytes& packet) {
  if (packet.size() < 20 || (packet[0] >> 4) != 4) return;
  const auto ihl = static_cast<std::size_t>((packet[0] & 0x0f) * 4);
  if (ihl < 20 || packet.size() < ihl) return;
  const auto total_len = get_u16(packet.data() + 2);
  if (total_len < ihl || total_len > packet.size()) return;
  packet.resize(total_len);

  put_u16_at(packet, 10, 0);
  put_u16_at(packet, 10, checksum_finish(checksum_sum(packet.data(), ihl)));

  const auto flags_fragment = get_u16(packet.data() + 6);
  const bool fragmented = (flags_fragment & 0x3fff) != 0;
  if (fragmented) return;

  const auto proto = packet[9];
  const std::size_t l4_len = total_len - ihl;
  auto pseudo_sum = [&]() {
    std::uint32_t sum = 0;
    sum = checksum_sum(packet.data() + 12, 8, sum);
    const std::uint8_t pseudo[4] = {0, proto, static_cast<std::uint8_t>(l4_len >> 8),
                                    static_cast<std::uint8_t>(l4_len)};
    return checksum_sum(pseudo, sizeof(pseudo), sum);
  };

  if (proto == 6 && l4_len >= 20) {
    put_u16_at(packet, ihl + 16, 0);
    put_u16_at(packet, ihl + 16, checksum_finish(checksum_sum(packet.data() + ihl, l4_len, pseudo_sum())));
  } else if (proto == 17 && l4_len >= 8) {
    put_u16_at(packet, ihl + 6, 0);
    auto sum = checksum_finish(checksum_sum(packet.data() + ihl, l4_len, pseudo_sum()));
    if (sum == 0) sum = 0xffff;
    put_u16_at(packet, ihl + 6, sum);
  } else if (proto == 1 && l4_len >= 4) {
    put_u16_at(packet, ihl + 2, 0);
    put_u16_at(packet, ihl + 2, checksum_finish(checksum_sum(packet.data() + ihl, l4_len)));
  }
}

Bytes make_frame(PacketType type,
                 const std::array<std::uint8_t, 16>& session_id,
                 std::uint64_t sequence,
                 const std::array<std::uint8_t, 32>& key,
                 const Bytes& plaintext) {
  WireHeader h;
  h.type = type;
  h.session_id = session_id;
  h.sequence = sequence;
  h.nonce = random_nonce12();
  h.ciphertext_len = static_cast<std::uint32_t>(plaintext.size() + 16);
  const auto aad = header_aad(h);
  auto ciphertext = aes256gcm_encrypt(key, h.nonce, plaintext, aad);
  auto frame = encode_header(h);
  frame.insert(frame.end(), ciphertext.begin(), ciphertext.end());
  return frame;
}

Bytes decrypt_frame(const Bytes& frame, const std::array<std::uint8_t, 32>& key, WireHeader* header) {
  *header = decode_header(frame.data(), frame.size());
  require(frame.size() == kHeaderSize + header->ciphertext_len, "nfq frame length mismatch");
  Bytes ciphertext(frame.begin() + kHeaderSize, frame.end());
  return aes256gcm_decrypt(key, header->nonce, ciphertext, header_aad(*header));
}

Metadata metadata_for_packet(const Bytes& packet,
                             std::uint64_t seq,
                             std::uint64_t send_ms,
                             std::uint64_t round_start,
                             const std::string& device_id) {
  const auto info = inspect_ip_packet(packet);
  Metadata meta;
  meta.sha = sha256(packet);
  meta.send_ms = send_ms;
  meta.round_start_ms = round_start;
  meta.sequence = seq;
  meta.source_device = device_id;
  meta.source_ip = info.source_ip;
  meta.destination_ip = info.destination_ip;
  meta.destination_port = info.destination_port;
  meta.ip_protocol = info.ip_protocol;
  meta.packet_length = static_cast<std::uint32_t>(packet.size());
  return meta;
}

std::string sanitize_for_filename(const std::string& text) {
  std::string out;
  for (char c : text) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
        c == '_' || c == '.') {
      out.push_back(c);
    } else {
      out.push_back('_');
    }
  }
  return out.empty() ? "packet" : out;
}

void write_binary_file(const std::filesystem::path& path, const Bytes& data) {
  std::ofstream out(path, std::ios::binary);
  require(out.good(), "cannot write quarantine file: " + path.string());
  out.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::filesystem::path quarantine_packet(NfqContext& ctx,
                                        const std::string& reason,
                                        const Metadata& meta,
                                        const Bytes& candidate_packet,
                                        const Bytes& wrapper_frame,
                                        const std::string& action,
                                        bool tag_ok,
                                        bool duplicate_sequence,
                                        bool same_sha_seen_before) {
  const auto base_dir = ctx.quarantine_dir.empty() ? std::filesystem::path("wiremark-quarantine")
                                                   : ctx.quarantine_dir;
  const auto dir = base_dir / sanitize_for_filename(reason);
  std::filesystem::create_directories(dir);
  const auto sha_hex = hex(meta.sha);
  const auto stem = std::to_string(now_ms()) + "-seq-" + std::to_string(meta.sequence) + "-" +
                    sha_hex.substr(0, 16);
  const auto packet_path = dir / (stem + ".packet.bin");
  const auto wrapper_path = dir / (stem + ".wrapper.bin");
  const auto manifest_path = dir / (stem + ".json");
  if (!candidate_packet.empty()) write_binary_file(packet_path, candidate_packet);
  if (!wrapper_frame.empty()) write_binary_file(wrapper_path, wrapper_frame);

  std::ofstream manifest(manifest_path);
  require(manifest.good(), "cannot write quarantine manifest: " + manifest_path.string());
  manifest << "{\n"
           << "  \"reason\": \"" << json_escape(reason) << "\",\n"
           << "  \"action\": \"" << json_escape(action) << "\",\n"
           << "  \"verify_ok\": " << (tag_ok ? "true" : "false") << ",\n"
           << "  \"verify_kind\": \"tag12\",\n"
           << "  \"duplicate_sequence\": " << (duplicate_sequence ? "true" : "false") << ",\n"
           << "  \"same_sha_seen_before\": " << (same_sha_seen_before ? "true" : "false") << ",\n"
           << "  \"seq\": " << meta.sequence << ",\n"
           << "  \"packet_sha256\": \"" << sha_hex << "\",\n"
           << "  \"source_device\": \"" << json_escape(meta.source_device) << "\",\n"
           << "  \"src_ip\": \"" << json_escape(meta.source_ip) << "\",\n"
           << "  \"dst_ip\": \"" << json_escape(meta.destination_ip) << "\",\n"
           << "  \"dst_port\": " << meta.destination_port << ",\n"
           << "  \"ip_proto\": " << static_cast<int>(meta.ip_protocol) << ",\n"
           << "  \"packet_len\": " << meta.packet_length << ",\n"
           << "  \"packet_file\": \"" << json_escape(candidate_packet.empty() ? "" : packet_path.string())
           << "\",\n"
           << "  \"wrapper_file\": \"" << json_escape(wrapper_frame.empty() ? "" : wrapper_path.string())
           << "\"\n"
           << "}\n";
  return manifest_path;
}

void log_decision(NfqContext& ctx,
                  const Metadata& meta,
                  const std::string& verdict,
                  PacketPolicy policy,
                  const std::string& action,
                  bool verify_ok,
                  bool duplicate_sequence,
                  bool same_sha_seen_before,
                  const std::filesystem::path& manifest_path) {
  DecisionRecord r;
  r.ms = now_ms();
  r.sequence = meta.sequence;
  r.verdict = verdict;
  r.action = action;
  r.policy = packet_policy_name(policy);
  r.origin = "peer_wrapper";
  r.verify_ok = verify_ok;
  r.verify_kind = "tag12";
  r.duplicate_sequence = duplicate_sequence;
  r.same_sha_seen_before = same_sha_seen_before;
  r.packet_sha256_hex = hex(meta.sha);
  r.quarantine_manifest = manifest_path.string();
  ctx.logger.decision(r);
}

PacketPolicy policy_for_verdict(const NfqContext& ctx, const std::string& verdict) {
  if (verdict == "verify_failed") return ctx.invalid_policy;
  if (verdict == "duplicate_sequence" || verdict == "replayed_wrapper") return ctx.replay_policy;
  if (verdict == "accepted") return PacketPolicy::Accept;
  return PacketPolicy::Drop;
}

struct UdpView {
  bool valid{false};
  std::uint8_t ihl{0};
  std::string src_ip;
  std::string dst_ip;
  std::uint16_t src_port{0};
  std::uint16_t dst_port{0};
  const std::uint8_t* payload{nullptr};
  std::size_t payload_len{0};
};

UdpView parse_udp_view(const Bytes& packet) {
  UdpView out;
  if (packet.size() < 28) return out;
  if ((packet[0] >> 4) != 4) return out;
  out.ihl = static_cast<std::uint8_t>((packet[0] & 0x0f) * 4);
  if (out.ihl < 20 || packet.size() < static_cast<std::size_t>(out.ihl) + 8) return out;
  if (packet[9] != 17) return out;
  const auto total_len = get_u16(packet.data() + 2);
  if (total_len < out.ihl + 8 || total_len > packet.size()) return out;
  char src[INET_ADDRSTRLEN]{};
  char dst[INET_ADDRSTRLEN]{};
  ::inet_ntop(AF_INET, packet.data() + 12, src, sizeof(src));
  ::inet_ntop(AF_INET, packet.data() + 16, dst, sizeof(dst));
  out.src_ip = src;
  out.dst_ip = dst;
  const auto* udp = packet.data() + out.ihl;
  out.src_port = get_u16(udp);
  out.dst_port = get_u16(udp + 2);
  const auto udp_len = get_u16(udp + 4);
  if (udp_len < 8 || out.ihl + udp_len > total_len) return out;
  out.payload = udp + 8;
  out.payload_len = udp_len - 8;
  out.valid = true;
  return out;
}

bool is_wrapper_packet(const Bytes& packet, std::uint16_t wrapper_port, Bytes* payload) {
  const auto udp = parse_udp_view(packet);
  if (!udp.valid) return false;
  if (udp.src_port != wrapper_port && udp.dst_port != wrapper_port) return false;
  payload->assign(udp.payload, udp.payload + udp.payload_len);
  return true;
}

Bytes encode_fragment(std::uint64_t frame_id, std::uint16_t index, std::uint16_t count, const Bytes& chunk) {
  Bytes out;
  put_u32(out, kFragMagic);
  put_u64(out, frame_id);
  put_u16(out, index);
  put_u16(out, count);
  put_u16(out, static_cast<std::uint16_t>(chunk.size()));
  put_u16(out, 0);
  out.insert(out.end(), chunk.begin(), chunk.end());
  return out;
}

void send_wrapper_frame(NfqContext& ctx, const Bytes& frame) {
  require(ctx.wrapper_mtu > kFragHeaderSize + 256, "wrapper MTU is too small");
  const std::size_t chunk_size = ctx.wrapper_mtu - kFragHeaderSize;
  const auto count = static_cast<std::uint16_t>((frame.size() + chunk_size - 1) / chunk_size);
  require(count > 0, "empty wrapper frame");
  require(count <= 1024, "wrapper frame has too many fragments");
  const auto frame_id = ctx.frame_seq++;
  for (std::uint16_t i = 0; i < count; ++i) {
    const auto start = static_cast<std::size_t>(i) * chunk_size;
    const auto end = std::min(start + chunk_size, frame.size());
    Bytes chunk(frame.begin() + start, frame.begin() + end);
    ctx.udp.send(encode_fragment(frame_id, i, count, chunk));
  }
}

std::string fragment_key(const UdpView& udp, std::uint64_t frame_id) {
  std::ostringstream os;
  os << udp.src_ip << ':' << udp.src_port << ':' << frame_id;
  return os.str();
}

void cleanup_fragments(NfqContext& ctx) {
  const auto cutoff = now_ms() - 30000;
  for (auto it = ctx.fragments.begin(); it != ctx.fragments.end();) {
    if (it->second.first_ms < cutoff) it = ctx.fragments.erase(it);
    else ++it;
  }
}

std::optional<Bytes> accept_fragment(NfqContext& ctx, const UdpView& udp) {
  if (udp.payload_len < kFragHeaderSize) throw std::runtime_error("wrapper fragment too short");
  if (get_u32(udp.payload) != kFragMagic) throw std::runtime_error("bad wrapper fragment magic");
  const auto frame_id = get_u64(udp.payload + 4);
  const auto index = get_u16(udp.payload + 12);
  const auto count = get_u16(udp.payload + 14);
  const auto len = get_u16(udp.payload + 16);
  require(count > 0 && count <= 1024, "bad wrapper fragment count");
  require(index < count, "bad wrapper fragment index");
  require(kFragHeaderSize + len == udp.payload_len, "bad wrapper fragment length");

  cleanup_fragments(ctx);
  auto& buf = ctx.fragments[fragment_key(udp, frame_id)];
  if (buf.parts.empty()) {
    buf.first_ms = now_ms();
    buf.count = count;
    buf.parts.resize(count);
  }
  require(buf.count == count, "fragment count changed");
  if (buf.parts[index].empty()) {
    buf.parts[index].assign(udp.payload + kFragHeaderSize, udp.payload + kFragHeaderSize + len);
    ++buf.received;
    buf.total_len += len;
  }
  if (buf.received != buf.count) return std::nullopt;

  Bytes frame;
  frame.reserve(buf.total_len);
  for (const auto& part : buf.parts) {
    require(!part.empty(), "missing wrapper fragment");
    frame.insert(frame.end(), part.begin(), part.end());
  }
  ctx.fragments.erase(fragment_key(udp, frame_id));
  return frame;
}

int verdict_with_candidate(nfq_q_handle* qh, std::uint32_t id, PacketPolicy policy, Bytes candidate_packet) {
  if (policy == PacketPolicy::Drop) return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
  finalize_ipv4_checksums(candidate_packet);
  return nfq_set_verdict(qh, id, NF_ACCEPT, static_cast<std::uint32_t>(candidate_packet.size()),
                         candidate_packet.data());
}

int accept_inner_packet(nfq_q_handle* qh,
                        std::uint32_t id,
                        NfqContext& ctx,
                        const Bytes& frame,
                        const Endpoint& verified_peer) {
  WireHeader h;
  auto plaintext = decrypt_frame(frame, ctx.keys.data_key, &h);
  require(h.type == PacketType::Data, "wrapper frame is not data");
  auto decoded = decode_compact_batch(plaintext);
  require(decoded.size() == 1, "nfq wrapper currently requires one packet per frame");
  const auto& cp = decoded.front();
  const bool verify_ok = cp.tag == tag12(ctx.keys.integrity_key, cp.sequence, cp.packet);
  auto meta = metadata_for_packet(cp.packet, cp.sequence, 0, ctx.round_start, "peer");
  const auto packet_sha = sha256(cp.packet);
  const auto replay_key = std::make_pair(h.session_id, cp.sequence);
  const bool duplicate_sequence = ctx.seen_sequences.find(replay_key) != ctx.seen_sequences.end();
  const bool same_sha_seen_before = ctx.seen_hashes.find(packet_sha) != ctx.seen_hashes.end();
  ctx.logger.received(meta, now_ms(), verify_ok, "tag12", same_sha_seen_before);

  if (verify_ok && !duplicate_sequence) {
    ctx.udp.set_peer(verified_peer);
    ctx.seen_sequences.insert(replay_key);
    ctx.seen_hashes.insert(packet_sha);
    log_decision(ctx, meta, "accepted", PacketPolicy::Accept, "accept_restored", true, false,
                 same_sha_seen_before, {});
    Bytes restored = cp.packet;
    finalize_ipv4_checksums(restored);
    return nfq_set_verdict(qh, id, NF_ACCEPT, static_cast<std::uint32_t>(restored.size()), restored.data());
  }

  const std::string verdict = verify_ok ? "duplicate_sequence" : "verify_failed";
  const auto policy = policy_for_verdict(ctx, verdict);
  const auto action = policy == PacketPolicy::Accept ? "accept_candidate" : "drop";
  const auto manifest = quarantine_packet(ctx, verdict, meta, cp.packet, frame, action, verify_ok,
                                          duplicate_sequence, same_sha_seen_before);
  log_decision(ctx, meta, verdict, policy, action, verify_ok, duplicate_sequence, same_sha_seen_before, manifest);
  return verdict_with_candidate(qh, id, policy, cp.packet);
}

int nfq_callback(nfq_q_handle* qh, nfgenmsg*, nfq_data* data, void* opaque) {
  auto* ctx = static_cast<NfqContext*>(opaque);
  nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(data);
  const std::uint32_t id = ph ? ntohl(ph->packet_id) : 0;

  unsigned char* raw = nullptr;
  const int len = nfq_get_payload(data, &raw);
  if (len <= 0 || raw == nullptr) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

  try {
    Bytes packet(raw, raw + len);
    const auto udp = parse_udp_view(packet);
    Bytes wrapper_payload;
    if (is_wrapper_packet(packet, ctx->wrapper_port, &wrapper_payload)) {
      const bool inbound = nfq_get_indev(data) != 0 || nfq_get_physindev(data) != 0;
      const bool has_wrapper_magic =
          wrapper_payload.size() >= kFragHeaderSize && get_u32(wrapper_payload.data()) == kFragMagic;
      if (!inbound && has_wrapper_magic) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
      if (inbound || has_wrapper_magic) {
        try {
          if (!has_wrapper_magic) throw std::runtime_error("bad wrapper fragment magic");
          auto frame = accept_fragment(*ctx, udp);
          if (!frame) return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
          return accept_inner_packet(qh, id, *ctx, *frame, Endpoint{udp.src_ip, udp.src_port});
        } catch (const std::exception& e) {
          auto meta = metadata_for_packet(packet, 0, 0, ctx->round_start, "peer_wrapper");
          const auto policy = ctx->invalid_policy;
          const auto action = policy == PacketPolicy::Accept ? "accept_wrapper" : "drop";
          const auto manifest = quarantine_packet(*ctx, "wrapper_decode_error", meta, {}, packet, action, false,
                                                  false, false);
          log_decision(*ctx, meta, "verify_failed", policy, action, false, false, false, manifest);
          ctx->logger.event("wrapper_decode_error", e.what());
          return policy == PacketPolicy::Accept ? nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr)
                                                : nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
        }
      }
    }

    finalize_ipv4_checksums(packet);
    const auto meta = metadata_for_packet(packet, ctx->data_seq++, now_ms(), ctx->round_start, ctx->device_id);
    CompactPacket cp;
    cp.sequence = meta.sequence;
    cp.packet = packet;
    cp.tag = tag12(ctx->keys.integrity_key, cp.sequence, cp.packet);
    const auto plaintext = encode_compact_batch(cp.sequence, std::vector<CompactPacket>{cp});
    send_wrapper_frame(*ctx, make_frame(PacketType::Data, ctx->session_id, meta.sequence, ctx->keys.data_key, plaintext));
    ctx->logger.sent(meta);
    return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
  } catch (const std::exception& e) {
    ctx->logger.event("nfq_wrap_error", e.what());
    return nfq_set_verdict(qh, id, ctx->fail_closed ? NF_DROP : NF_ACCEPT, 0, nullptr);
  }
}

struct NfqHandle {
  nfq_handle* h{nullptr};
  nfq_q_handle* qh{nullptr};
  ~NfqHandle() {
    if (qh) nfq_destroy_queue(qh);
    if (h) nfq_close(h);
  }
};

}  // namespace

void run_nfq_gateway(const NfqGatewayConfig& cfg, Logger& logger) {
  std::signal(SIGINT, on_nfq_signal);
  std::signal(SIGTERM, on_nfq_signal);
  NfqContext ctx(cfg, logger);
  NfqHandle nfq;
  nfq.h = nfq_open();
  require(nfq.h != nullptr, "nfq_open failed");
  if (nfq_unbind_pf(nfq.h, AF_INET) < 0 && errno != EINVAL) {
    logger.event("nfq_unbind_pf_warning", std::strerror(errno));
  }
  if (nfq_bind_pf(nfq.h, AF_INET) < 0) {
    logger.event("nfq_bind_pf_warning", std::strerror(errno));
  }
  nfq.qh = nfq_create_queue(nfq.h, cfg.queue_num, &nfq_callback, &ctx);
  if (nfq.qh == nullptr) {
    throw std::runtime_error(std::string("nfq_create_queue failed: ") + std::strerror(errno) +
                             " (kernel needs nfnetlink_queue support)");
  }
  require(nfq_set_mode(nfq.qh, NFQNL_COPY_PACKET, 0xffff) >= 0, "nfq_set_mode failed");

  const int nfd = nfq_fd(nfq.h);
  logger.event("nfq_started", "queue=" + std::to_string(cfg.queue_num));
  while (!g_nfq_stop) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(nfd, &rfds);
    const int maxfd = nfd + 1;
    timeval tv{1, 0};
    const int rc = ::select(maxfd, &rfds, nullptr, nullptr, &tv);
    if (rc < 0) {
      if (errno == EINTR) continue;
      throw std::runtime_error(std::string("nfq select failed: ") + std::strerror(errno));
    }
    if (FD_ISSET(nfd, &rfds)) {
      std::array<char, 65536> buf{};
      const int n = ::recv(nfd, buf.data(), buf.size(), 0);
      if (n >= 0) nfq_handle_packet(nfq.h, buf.data(), n);
    }
  }
  logger.event("nfq_stopped", "done");
}

}  // namespace wiremark
