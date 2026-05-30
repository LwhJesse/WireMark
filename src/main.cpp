#include "wiremark/crypto.hpp"
#include "wiremark/capture.hpp"
#include "wiremark/compact.hpp"
#include "wiremark/logger.hpp"
#include "wiremark/netif.hpp"
#include "wiremark/nfq_gateway.hpp"
#include "wiremark/protocol.hpp"
#include "wiremark/tcp.hpp"
#include "wiremark/tun.hpp"
#include "wiremark/udp.hpp"

#include <sys/select.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <array>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) {
  g_stop = 1;
}

struct Config {
  std::string mode = "run";
  std::string tun = "wm0";
  wiremark::Endpoint listen{"0.0.0.0", 44330};
  wiremark::Endpoint peer{"127.0.0.1", 44330};
  std::string key_file;
  std::string device_id = "wiremark-node";
  std::filesystem::path log_dir = "logs";
  std::string session;
  bool root_check = true;
  std::uint64_t probe_count = 0;
  std::uint64_t interval_ms = 100;
  std::string capture_iface;
  std::string capture_peer;
  std::uint16_t capture_port = 443;
  std::uint64_t capture_seconds = 30;
  bool capture_payload_only = false;
  std::string transport = "udp";
  std::uint16_t nfq_queue = 70;
  std::uint16_t wrapper_mtu = 1200;
  std::filesystem::path quarantine_dir;
  bool fail_closed = true;
  wiremark::PacketPolicy invalid_policy = wiremark::PacketPolicy::Drop;
  wiremark::PacketPolicy replay_policy = wiremark::PacketPolicy::Drop;
  bool tun_arg_seen = false;
  bool transport_arg_seen = false;
};

void usage() {
  std::cerr
      << "Usage:\n"
      << "  wiremark selftest\n"
      << "  wiremark doctor [--peer-ip PEER_IP]\n"
      << "  wiremark interfaces [--peer-ip PEER_IP]\n"
      << "  wiremark run --queue-num 70 --listen 0.0.0.0:47000 --peer host:47000 \\\n"
      << "    --key-file wiremark.key --device-id node --log-dir logs --session name \\\n"
      << "    [--wrapper-mtu 1200] [--quarantine-dir DIR] \\\n"
      << "    [--invalid-policy drop|accept] [--replay-policy drop|accept] [--fail-open]\n"
      << "  wiremark capture --iface auto|wlan0 --peer-ip PEER_IP --port 443 \\\n"
      << "    --seconds 30 --log-dir logs --session capture-session\n"
      << "  wiremark probe --listen 0.0.0.0:44330 --peer host:44330|auto \\\n"
      << "    --key-file wiremark.key --device-id node --log-dir logs [--count 100]\n"
      << "  wiremark tun --tun wm0 --listen 0.0.0.0:44330 --peer host:44330 \\\n"
      << "    --key-file wiremark.key --device-id wiremark-node --log-dir logs [--session name]\n"
      << "    [--transport udp|tcp-listen|tcp-connect]\n"
      << "\nPolicy defaults: --invalid-policy drop and --replay-policy drop. "
      << "--invalid-policy accept is unsafe/debug only: it disables WireMark's "
      << "core integrity guarantee for authentication failures. Repeated packet "
      << "SHA256 is logged as same_sha_seen_before only; it is not a drop policy.\n";
}


std::uint16_t parse_u16_option(const std::string& name,
                               const std::string& value,
                               unsigned long min_value,
                               unsigned long max_value) {
  std::size_t pos = 0;
  const auto parsed = std::stoul(value, &pos);
  if (pos != value.size() || parsed < min_value || parsed > max_value) {
    throw std::runtime_error(name + " out of range: " + value);
  }
  return static_cast<std::uint16_t>(parsed);
}

std::string running_kernel() {
  utsname u{};
  if (::uname(&u) != 0) return "unknown";
  return u.release;
}

bool path_contains_name(const std::filesystem::path& root, const std::string& needle) {
  std::error_code ec;
  if (!std::filesystem::exists(root, ec)) return false;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root, ec)) {
    if (ec) break;
    if (entry.path().filename().string().find(needle) != std::string::npos) return true;
  }
  return false;
}

int doctor(const std::string& peer_ip) {
  const auto kernel = running_kernel();
  const auto module_dir = std::filesystem::path("/lib/modules") / kernel;
  std::cout << "WireMark doctor\n";
  std::cout << "kernel=" << kernel << "\n";
#ifdef WIREMARK_HAVE_NFQUEUE
  std::cout << "built_with_nfqueue=yes\n";
#else
  std::cout << "built_with_nfqueue=no\n";
#endif
  std::cout << "module_dir=" << module_dir << " exists="
            << (std::filesystem::exists(module_dir) ? "yes" : "no") << "\n";
  std::cout << "module_nfnetlink_queue="
            << (path_contains_name(module_dir, "nfnetlink_queue") ? "yes" : "no") << "\n";
  std::cout << "module_xt_NFQUEUE=" << (path_contains_name(module_dir, "xt_NFQUEUE") ? "yes" : "no")
            << "\n";
  std::cout << "module_sch_ingress=" << (path_contains_name(module_dir, "sch_ingress") ? "yes" : "no")
            << "\n";
  std::cout << "module_cls_bpf=" << (path_contains_name(module_dir, "cls_bpf") ? "yes" : "no") << "\n";
  std::cout << "module_act_bpf=" << (path_contains_name(module_dir, "act_bpf") ? "yes" : "no") << "\n";
  wiremark::print_interface_plan(peer_ip);
  return 0;
}

Config parse_args(int argc, char** argv) {
  if (argc < 2 || (std::string(argv[1]) != "run" && std::string(argv[1]) != "tun" &&
                   std::string(argv[1]) != "probe" &&
                   std::string(argv[1]) != "capture" && std::string(argv[1]) != "interfaces" &&
                   std::string(argv[1]) != "doctor" && std::string(argv[1]) != "nfq")) {
    usage();
    std::exit(2);
  }
  Config c;
  c.mode = argv[1];
  c.session = "wiremark-" + std::to_string(wiremark::now_ms());
  for (int i = 2; i < argc; ++i) {
    const std::string k = argv[i];
    auto need_value = [&](const std::string& name) -> std::string {
      if (i + 1 >= argc) throw std::runtime_error("missing value for " + name);
      return argv[++i];
    };
    if (k == "--tun") {
      c.tun = need_value(k);
      c.tun_arg_seen = true;
    }
    else if (k == "--listen") c.listen = wiremark::parse_endpoint(need_value(k));
    else if (k == "--peer") c.peer = wiremark::parse_endpoint(need_value(k));
    else if (k == "--key-file") c.key_file = need_value(k);
    else if (k == "--device-id") c.device_id = need_value(k);
    else if (k == "--log-dir") c.log_dir = need_value(k);
    else if (k == "--session") c.session = need_value(k);
    else if (k == "--no-root-check") c.root_check = false;
    else if (k == "--count") c.probe_count = std::stoull(need_value(k));
    else if (k == "--interval-ms") c.interval_ms = std::stoull(need_value(k));
    else if (k == "--iface") c.capture_iface = need_value(k);
    else if (k == "--peer-ip") c.capture_peer = need_value(k);
    else if (k == "--port") c.capture_port = parse_u16_option(k, need_value(k), 1, 65535);
    else if (k == "--seconds") c.capture_seconds = std::stoull(need_value(k));
    else if (k == "--payload-only") c.capture_payload_only = true;
    else if (k == "--transport") {
      c.transport = need_value(k);
      c.transport_arg_seen = true;
    }
    else if (k == "--queue-num") c.nfq_queue = parse_u16_option(k, need_value(k), 0, 65535);
    else if (k == "--wrapper-mtu") c.wrapper_mtu = parse_u16_option(k, need_value(k), 277, 65535);
    else if (k == "--quarantine-dir") c.quarantine_dir = need_value(k);
    else if (k == "--invalid-policy") c.invalid_policy = wiremark::parse_packet_policy(need_value(k));
    else if (k == "--replay-policy") c.replay_policy = wiremark::parse_packet_policy(need_value(k));
    else if (k == "--fail-open") c.fail_closed = false;
    else throw std::runtime_error("unknown argument: " + k);
  }
  if (c.mode != "capture" && c.mode != "interfaces" && c.mode != "doctor") {
    wiremark::require(!c.key_file.empty(), "--key-file is required");
  }
  if (c.mode == "capture") wiremark::require(!c.capture_iface.empty(), "--iface is required");
  if (c.mode == "run" || c.mode == "nfq") {
    wiremark::require(!c.tun_arg_seen, "--tun is only valid with explicit 'wiremark tun'");
    wiremark::require(!c.transport_arg_seen, "--transport is only valid with explicit 'wiremark tun'");
  }
  return c;
}

wiremark::Bytes make_probe_ip_packet(std::uint64_t seq) {
  wiremark::Bytes p(28, 0);
  p[0] = 0x45;
  p[2] = 0;
  p[3] = 28;
  p[8] = 64;
  p[9] = 17;
  p[12] = 10;
  p[13] = 250;
  p[14] = static_cast<std::uint8_t>((seq >> 8) & 0xff);
  p[15] = static_cast<std::uint8_t>(seq & 0xff);
  p[16] = 10;
  p[17] = 251;
  p[18] = static_cast<std::uint8_t>((seq >> 8) & 0xff);
  p[19] = static_cast<std::uint8_t>(seq & 0xff);
  p[20] = 0x9c;
  p[21] = 0x40;
  p[22] = 0x9c;
  p[23] = 0x41;
  p[24] = 0;
  p[25] = 8;
  return p;
}

std::array<std::uint8_t, 16> random_session_id() {
  std::array<std::uint8_t, 16> out{};
  const auto r = wiremark::random_bytes(out.size());
  std::copy(r.begin(), r.end(), out.begin());
  return out;
}

std::array<std::uint8_t, 12> random_nonce() {
  std::array<std::uint8_t, 12> out{};
  const auto r = wiremark::random_bytes(out.size());
  std::copy(r.begin(), r.end(), out.begin());
  return out;
}

wiremark::Bytes make_frame(wiremark::PacketType type,
                           const std::array<std::uint8_t, 16>& session_id,
                           std::uint64_t sequence,
                           const std::array<std::uint8_t, 32>& key,
                           const wiremark::Bytes& plaintext) {
  wiremark::WireHeader h;
  h.type = type;
  h.session_id = session_id;
  h.sequence = sequence;
  h.nonce = random_nonce();
  h.ciphertext_len = static_cast<std::uint32_t>(plaintext.size() + 16);
  const auto aad = wiremark::header_aad(h);
  auto ciphertext = wiremark::aes256gcm_encrypt(key, h.nonce, plaintext, aad);
  auto frame = wiremark::encode_header(h);
  frame.insert(frame.end(), ciphertext.begin(), ciphertext.end());
  return frame;
}

wiremark::Bytes decrypt_frame(const wiremark::Bytes& frame,
                              const std::array<std::uint8_t, 32>& key,
                              wiremark::WireHeader* header) {
  *header = wiremark::decode_header(frame.data(), frame.size());
  wiremark::require(frame.size() == wiremark::kHeaderSize + header->ciphertext_len,
                    "frame length does not match header");
  wiremark::Bytes ciphertext(frame.begin() + wiremark::kHeaderSize, frame.end());
  return wiremark::aes256gcm_decrypt(key, header->nonce, ciphertext, wiremark::header_aad(*header));
}

wiremark::Bytes make_control_plaintext(const std::string& name, const wiremark::Bytes& data) {
  wiremark::Bytes out;
  wiremark::put_u16(out, static_cast<std::uint16_t>(wiremark::TlvType::LogName));
  wiremark::put_u32(out, static_cast<std::uint32_t>(name.size()));
  out.insert(out.end(), name.begin(), name.end());
  wiremark::put_u16(out, static_cast<std::uint16_t>(wiremark::TlvType::LogData));
  wiremark::put_u32(out, static_cast<std::uint32_t>(data.size()));
  out.insert(out.end(), data.begin(), data.end());
  return out;
}

std::pair<std::string, wiremark::Bytes> parse_control_plaintext(const wiremark::Bytes& p) {
  std::string name;
  wiremark::Bytes data;
  std::size_t pos = 0;
  while (pos + 6 <= p.size()) {
    const auto type = wiremark::get_u16(p.data() + pos);
    const auto len = wiremark::get_u32(p.data() + pos + 2);
    pos += 6;
    wiremark::require(pos + len <= p.size(), "truncated control tlv");
    if (type == static_cast<std::uint16_t>(wiremark::TlvType::LogName)) {
      name.assign(reinterpret_cast<const char*>(p.data() + pos), len);
    } else if (type == static_cast<std::uint16_t>(wiremark::TlvType::LogData)) {
      data.assign(p.begin() + pos, p.begin() + pos + len);
    }
    pos += len;
  }
  return {name, data};
}

int selftest() {
  const wiremark::Bytes secret = wiremark::string_as_bytes("0123456789abcdef0123456789abcdef");
  const auto keys = wiremark::derive_keys(secret, "udp-v1");
  const auto session_id = random_session_id();

  wiremark::Bytes packet = {
      0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
      10,   0,    0,    1,    10,   0,    0,    2,    0x30, 0x39, 0x01, 0xbb,
      0x00, 0x08, 0x00, 0x00,
  };
  auto info = wiremark::inspect_ip_packet(packet);
  wiremark::Metadata meta;
  meta.sha = wiremark::sha256(packet);
  meta.send_ms = wiremark::now_ms();
  meta.round_start_ms = meta.send_ms;
  meta.sequence = 7;
  meta.source_device = "selftest";
  meta.source_ip = info.source_ip;
  meta.destination_ip = info.destination_ip;
  meta.destination_port = info.destination_port;
  meta.ip_protocol = info.ip_protocol;
  meta.packet_length = static_cast<std::uint32_t>(packet.size());

  auto frame = make_frame(wiremark::PacketType::Data, session_id, meta.sequence, keys.data_key,
                          wiremark::make_plaintext(meta, packet));
  wiremark::WireHeader h;
  auto plain = decrypt_frame(frame, keys.data_key, &h);
  auto [decoded_meta, decoded_packet] = wiremark::split_plaintext(plain);
  wiremark::require(decoded_packet == packet, "selftest packet mismatch");
  wiremark::require(decoded_meta.sha == wiremark::sha256(decoded_packet), "selftest sha mismatch");
  wiremark::require(decoded_meta.destination_ip == "10.0.0.2", "selftest destination ip mismatch");
  wiremark::require(decoded_meta.destination_port == 443, "selftest destination port mismatch");

  auto control_frame = make_frame(wiremark::PacketType::LogChunk, session_id, 1, keys.control_key,
                                  make_control_plaintext("x.log", wiremark::string_as_bytes("ok")));
  auto control_plain = decrypt_frame(control_frame, keys.control_key, &h);
  auto [name, data] = parse_control_plaintext(control_plain);
  wiremark::require(name == "x.log" && wiremark::bytes_as_string(data) == "ok", "selftest control mismatch");

  wiremark::CompactPacket cp;
  cp.sequence = 42;
  cp.packet = packet;
  cp.tag = wiremark::tag12(keys.integrity_key, cp.sequence, cp.packet);
  auto compact_plain = wiremark::encode_compact_batch(cp.sequence, std::vector<wiremark::CompactPacket>{cp});
  auto compact_frame = make_frame(wiremark::PacketType::Data, session_id, 2, keys.data_key, compact_plain);
  auto decoded_plain = decrypt_frame(compact_frame, keys.data_key, &h);
  auto decoded_batch = wiremark::decode_compact_batch(decoded_plain);
  wiremark::require(decoded_batch.size() == 1, "selftest compact count mismatch");
  wiremark::require(decoded_batch[0].packet == packet, "selftest compact packet mismatch");
  wiremark::require(decoded_batch[0].tag == wiremark::tag12(keys.integrity_key, decoded_batch[0].sequence,
                                                            decoded_batch[0].packet),
                    "selftest compact tag mismatch");
  std::cout << "selftest ok\n";
  return 0;
}

void send_log_file(wiremark::UdpSocket& udp,
                   const std::array<std::uint8_t, 16>& session_id,
                   const std::array<std::uint8_t, 32>& control_key,
                   std::uint64_t& control_seq,
                   const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.good()) return;
  constexpr std::size_t kChunk = 1200;
  std::array<char, kChunk> buf{};
  const auto name = path.filename().string();
  while (in.good()) {
    in.read(buf.data(), buf.size());
    const auto got = in.gcount();
    if (got <= 0) break;
    wiremark::Bytes data(buf.begin(), buf.begin() + got);
    udp.send(make_frame(wiremark::PacketType::LogChunk, session_id, control_seq++, control_key,
                        make_control_plaintext(name, data)));
  }
  udp.send(make_frame(wiremark::PacketType::LogDone, session_id, control_seq++, control_key,
                      make_control_plaintext(name, {})));
}

void drain_remote_logs(wiremark::UdpSocket& udp,
                       const std::array<std::uint8_t, 32>& control_key,
                       const std::filesystem::path& log_dir,
                       wiremark::Logger& logger) {
  const auto until = wiremark::now_ms() + 2000;
  while (wiremark::now_ms() < until) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udp.fd(), &rfds);
    timeval tv{0, 200000};
    const int rc = ::select(udp.fd() + 1, &rfds, nullptr, nullptr, &tv);
    if (rc <= 0 || !FD_ISSET(udp.fd(), &rfds)) continue;
    try {
      wiremark::Endpoint sender;
      auto frame = udp.recv_from(&sender);
      if (frame.size() < wiremark::kHeaderSize) continue;
      wiremark::WireHeader h;
      auto plaintext = decrypt_frame(frame, control_key, &h);
      udp.set_peer(sender);
      if (h.type != wiremark::PacketType::LogChunk && h.type != wiremark::PacketType::LogDone) continue;
      auto [name, data] = parse_control_plaintext(plaintext);
      if (!name.empty()) {
        std::ofstream out(log_dir / ("remote-" + name), std::ios::binary | std::ios::app);
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
        logger.event(wiremark::packet_type_name(h.type), name);
      }
    } catch (const std::exception& e) {
      logger.event("control_receive_error", e.what());
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc >= 2 && std::string(argv[1]) == "selftest") return selftest();
    const Config cfg = parse_args(argc, argv);
    if (cfg.mode == "doctor") return doctor(cfg.capture_peer);
    if (cfg.mode == "interfaces") {
      wiremark::print_interface_plan(cfg.capture_peer);
      return 0;
    }

    if ((cfg.mode == "run" || cfg.mode == "tun" || cfg.mode == "capture" || cfg.mode == "nfq") &&
        cfg.root_check && ::geteuid() != 0) {
      throw std::runtime_error("root is required for this mode; rerun with sudo");
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    const auto session_id = random_session_id();
    const auto round_start = wiremark::now_ms();
    std::uint64_t data_seq = 1;
    std::uint64_t control_seq = 1;

    wiremark::Logger logger(cfg.log_dir, cfg.session);
    if (cfg.mode == "run" || cfg.mode == "nfq") {
      wiremark::NfqGatewayConfig nc;
      nc.queue_num = cfg.nfq_queue;
      nc.listen = cfg.listen;
      nc.peer = cfg.peer;
      nc.device_id = cfg.device_id;
      nc.key_file = cfg.key_file;
      nc.wrapper_mtu = cfg.wrapper_mtu;
      nc.fail_closed = cfg.fail_closed;
      nc.invalid_policy = cfg.invalid_policy;
      nc.replay_policy = cfg.replay_policy;
      nc.quarantine_dir = cfg.quarantine_dir.empty() ? cfg.log_dir / "quarantine" : cfg.quarantine_dir;
      std::cerr << "WireMark lowest active NFQUEUE gateway running on queue " << nc.queue_num
                << ". Install NFQUEUE rules separately. Stop with Ctrl-C.\n";
      wiremark::run_nfq_gateway(nc, logger);
      logger.write_summary(round_start, wiremark::now_ms());
      std::cerr << "WireMark NFQUEUE gateway stopped. Logs: " << logger.packet_log_path() << " and "
                << logger.summary_path() << "\n";
      return 0;
    }
    if (cfg.mode == "capture") {
      wiremark::CaptureConfig cc;
      cc.iface = cfg.capture_iface;
      if (cc.iface == "auto") {
        const auto selected = wiremark::choose_lowest_interface(cfg.capture_peer);
        wiremark::require(selected.has_value(), "could not auto-select a capture interface");
        cc.iface = selected->name;
        logger.event("iface_auto_selected", cc.iface + " layer=" + wiremark::interface_layer_name(selected->layer) +
                                                " reason=" + selected->reason);
        std::cerr << "WireMark selected interface " << cc.iface << " (" << selected->reason << ")\n";
      }
      cc.peer_ip = cfg.capture_peer;
      cc.port = cfg.capture_port;
      cc.seconds = cfg.capture_seconds;
      cc.payload_only = cfg.capture_payload_only;
      wiremark::capture_udp(cc, logger);
      logger.write_summary(round_start, wiremark::now_ms());
      std::cerr << "WireMark capture stopped. Logs: " << logger.packet_log_path() << "\n";
      return 0;
    }

    const auto secret = wiremark::read_key_file(cfg.key_file);
    const auto keys = wiremark::derive_keys(secret, "udp-v1");
    if (cfg.mode == "probe") {
      wiremark::UdpSocket udp(cfg.listen, cfg.peer);
      logger.event("probe_started", "listen=" + cfg.listen.host + ":" + std::to_string(cfg.listen.port));
      std::cerr << "WireMark probe running. Stop with Ctrl-C.\n";
      auto next_send = round_start;
      while (!g_stop) {
        const auto t = wiremark::now_ms();
        if (cfg.probe_count > 0 && data_seq <= cfg.probe_count && udp.has_peer() && t >= next_send) {
          auto packet = make_probe_ip_packet(data_seq);
          auto info = wiremark::inspect_ip_packet(packet);
          wiremark::Metadata meta;
          meta.sha = wiremark::sha256(packet);
          meta.send_ms = t;
          meta.round_start_ms = round_start;
          meta.sequence = data_seq++;
          meta.source_device = cfg.device_id;
          meta.source_ip = info.source_ip;
          meta.destination_ip = info.destination_ip;
          meta.destination_port = info.destination_port;
          meta.ip_protocol = info.ip_protocol;
          meta.packet_length = static_cast<std::uint32_t>(packet.size());
          udp.send(make_frame(wiremark::PacketType::Data, session_id, meta.sequence, keys.data_key,
                              wiremark::make_plaintext(meta, packet)));
          logger.sent(meta);
          next_send = t + cfg.interval_ms;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(udp.fd(), &rfds);
        timeval tv{0, 100000};
        const int rc = ::select(udp.fd() + 1, &rfds, nullptr, nullptr, &tv);
        if (rc > 0 && FD_ISSET(udp.fd(), &rfds)) {
          try {
            wiremark::Endpoint sender;
            auto frame = udp.recv_from(&sender);
            if (frame.size() < wiremark::kHeaderSize) continue;
            const auto type = static_cast<wiremark::PacketType>(frame[5]);
            const auto& key = type == wiremark::PacketType::Data ? keys.data_key : keys.control_key;
            wiremark::WireHeader h;
            auto plaintext = decrypt_frame(frame, key, &h);
            udp.set_peer(sender);
            if (h.type == wiremark::PacketType::Data) {
              auto [meta, packet] = wiremark::split_plaintext(plaintext);
              logger.received(meta, wiremark::now_ms(), true, "aes256gcm");
            } else {
              auto [name, data] = parse_control_plaintext(plaintext);
              if (!name.empty()) {
                std::ofstream out(cfg.log_dir / ("remote-" + name), std::ios::binary | std::ios::app);
                out.write(reinterpret_cast<const char*>(data.data()), data.size());
                logger.event(wiremark::packet_type_name(h.type), name);
              }
            }
          } catch (const std::exception& e) {
            logger.event("probe_receive_error", e.what());
          }
        }
        if (cfg.probe_count > 0 && data_seq > cfg.probe_count) {
          const auto wait_until = wiremark::now_ms() + 1000;
          while (wiremark::now_ms() < wait_until) {
            fd_set more;
            FD_ZERO(&more);
            FD_SET(udp.fd(), &more);
            timeval wtv{0, 100000};
            if (::select(udp.fd() + 1, &more, nullptr, nullptr, &wtv) > 0 && FD_ISSET(udp.fd(), &more)) {
              wiremark::Endpoint sender;
              auto frame = udp.recv_from(&sender);
              if (frame.size() < wiremark::kHeaderSize) continue;
              const auto type = static_cast<wiremark::PacketType>(frame[5]);
              if (type != wiremark::PacketType::Data) continue;
              wiremark::WireHeader h;
              auto plaintext = decrypt_frame(frame, keys.data_key, &h);
              udp.set_peer(sender);
              auto [meta, packet] = wiremark::split_plaintext(plaintext);
              logger.received(meta, wiremark::now_ms(), true, "aes256gcm");
            }
          }
          break;
        }
      }
      logger.write_summary(round_start, wiremark::now_ms());
      send_log_file(udp, session_id, keys.control_key, control_seq, logger.packet_log_path());
      send_log_file(udp, session_id, keys.control_key, control_seq, logger.summary_path());
      drain_remote_logs(udp, keys.control_key, cfg.log_dir, logger);
      std::cerr << "WireMark probe stopped. Logs: " << logger.packet_log_path() << " and "
                << logger.summary_path() << "\n";
      return 0;
    }

    wiremark::require(cfg.mode == "tun", "internal mode error: expected explicit tun mode");
    wiremark::TunDevice tun(cfg.tun);
    std::unique_ptr<wiremark::UdpSocket> udp;
    std::unique_ptr<wiremark::TcpStream> tcp;
    if (cfg.transport == "udp") {
      udp = std::make_unique<wiremark::UdpSocket>(cfg.listen, cfg.peer);
    } else if (cfg.transport == "tcp-listen") {
      std::cerr << "WireMark waiting for TCP transport on " << cfg.listen.host << ":" << cfg.listen.port << "\n";
      tcp = std::make_unique<wiremark::TcpStream>(wiremark::TcpStream::listen_one(cfg.listen));
    } else if (cfg.transport == "tcp-connect") {
      tcp = std::make_unique<wiremark::TcpStream>(wiremark::TcpStream::connect_to(cfg.peer));
    } else {
      throw std::runtime_error("unknown transport: " + cfg.transport);
    }
    auto transport_fd = [&]() { return udp ? udp->fd() : tcp->fd(); };
    auto send_transport = [&](const wiremark::Bytes& frame) {
      if (udp) udp->send(frame);
      else tcp->send_frame(frame);
    };
    wiremark::Endpoint last_transport_sender;
    bool last_transport_sender_valid = false;
    auto recv_transport = [&]() -> wiremark::Bytes {
      if (udp) {
        last_transport_sender_valid = true;
        return udp->recv_from(&last_transport_sender);
      }
      last_transport_sender_valid = false;
      return tcp->recv_frame();
    };
    logger.event("started", "tun=" + tun.name());
    std::cerr << "WireMark running on TUN " << tun.name() << ". Stop with Ctrl-C.\n";

    while (!g_stop) {
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(tun.fd(), &rfds);
      FD_SET(transport_fd(), &rfds);
      const int maxfd = std::max(tun.fd(), transport_fd()) + 1;
      timeval tv{1, 0};
      const int rc = ::select(maxfd, &rfds, nullptr, nullptr, &tv);
      if (rc < 0) {
        if (errno == EINTR) continue;
        throw std::runtime_error("select failed");
      }

      if (FD_ISSET(tun.fd(), &rfds)) {
        auto packet = tun.read_packet();
        auto info = wiremark::inspect_ip_packet(packet);
        wiremark::Metadata meta;
        meta.sha = wiremark::sha256(packet);
        meta.send_ms = wiremark::now_ms();
        meta.round_start_ms = round_start;
        meta.sequence = data_seq++;
        meta.source_device = cfg.device_id;
        meta.source_ip = info.source_ip;
        meta.destination_ip = info.destination_ip;
        meta.destination_port = info.destination_port;
        meta.ip_protocol = info.ip_protocol;
        meta.packet_length = static_cast<std::uint32_t>(packet.size());
        wiremark::CompactPacket cp;
        cp.sequence = meta.sequence;
        cp.packet = packet;
        cp.tag = wiremark::tag12(keys.integrity_key, cp.sequence, cp.packet);
        auto plaintext = wiremark::encode_compact_batch(cp.sequence, std::vector<wiremark::CompactPacket>{cp});
        send_transport(make_frame(wiremark::PacketType::Data, session_id, meta.sequence, keys.data_key, plaintext));
        logger.sent(meta);
      }

      if (FD_ISSET(transport_fd(), &rfds)) {
        try {
          auto frame = recv_transport();
          wiremark::WireHeader h;
          if (frame.size() < wiremark::kHeaderSize) continue;
          const auto type = static_cast<wiremark::PacketType>(frame[5]);
          const auto& key = type == wiremark::PacketType::Data ? keys.data_key : keys.control_key;
          auto plaintext = decrypt_frame(frame, key, &h);
          if (h.type == wiremark::PacketType::Data) {
            bool verified_any = false;
            for (auto& cp : wiremark::decode_compact_batch(plaintext)) {
              const bool ok = cp.tag == wiremark::tag12(keys.integrity_key, cp.sequence, cp.packet);
              const auto info = wiremark::inspect_ip_packet(cp.packet);
              wiremark::Metadata meta;
              meta.sha = wiremark::sha256(cp.packet);
              meta.send_ms = 0;
              meta.round_start_ms = round_start;
              meta.sequence = cp.sequence;
              meta.source_device = "peer";
              meta.source_ip = info.source_ip;
              meta.destination_ip = info.destination_ip;
              meta.destination_port = info.destination_port;
              meta.ip_protocol = info.ip_protocol;
              meta.packet_length = static_cast<std::uint32_t>(cp.packet.size());
              logger.received(meta, wiremark::now_ms(), ok, "tag12");
              if (ok) {
                verified_any = true;
                tun.write_packet(cp.packet);
              }
            }
            if (verified_any && udp && last_transport_sender_valid) udp->set_peer(last_transport_sender);
          } else {
            if (udp && last_transport_sender_valid) udp->set_peer(last_transport_sender);
            auto [name, data] = parse_control_plaintext(plaintext);
            if (!name.empty()) {
              const auto path = cfg.log_dir / ("remote-" + name);
              std::ofstream out(path, std::ios::binary | std::ios::app);
              out.write(reinterpret_cast<const char*>(data.data()), data.size());
              logger.event(wiremark::packet_type_name(h.type), name);
            }
          }
        } catch (const std::exception& e) {
          logger.event("receive_error", e.what());
        }
      }
    }

    const auto round_end = wiremark::now_ms();
    logger.write_summary(round_start, round_end);
    if (udp) {
      logger.event("stopping", "sending encrypted log copies to peer");
      send_log_file(*udp, session_id, keys.control_key, control_seq, logger.packet_log_path());
      send_log_file(*udp, session_id, keys.control_key, control_seq, logger.summary_path());
      drain_remote_logs(*udp, keys.control_key, cfg.log_dir, logger);
    }
    logger.event("stopped", "done");
    std::cerr << "WireMark stopped. Logs: " << logger.packet_log_path() << " and " << logger.summary_path()
              << "\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "wiremark: " << e.what() << "\n";
    return 1;
  }
}
