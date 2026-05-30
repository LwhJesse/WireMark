#include "wiremark/protocol.hpp"

#include <arpa/inet.h>

#include <cstring>

namespace wiremark {

Bytes encode_header(const WireHeader& h) {
  Bytes out;
  out.reserve(kHeaderSize);
  put_u32(out, kMagic);
  out.push_back(kVersion);
  out.push_back(static_cast<std::uint8_t>(h.type));
  put_u16(out, h.flags);
  out.insert(out.end(), h.session_id.begin(), h.session_id.end());
  put_u64(out, h.sequence);
  out.insert(out.end(), h.nonce.begin(), h.nonce.end());
  put_u32(out, h.ciphertext_len);
  return out;
}

WireHeader decode_header(const std::uint8_t* data, std::size_t len) {
  require(len >= kHeaderSize, "short wiremark header");
  require(get_u32(data) == kMagic, "bad wiremark magic");
  require(data[4] == kVersion, "unsupported wiremark version");
  WireHeader h;
  h.type = static_cast<PacketType>(data[5]);
  h.flags = get_u16(data + 6);
  std::memcpy(h.session_id.data(), data + 8, h.session_id.size());
  h.sequence = get_u64(data + 24);
  std::memcpy(h.nonce.data(), data + 32, h.nonce.size());
  h.ciphertext_len = get_u32(data + 44);
  require(h.ciphertext_len <= kMaxPacketSize + 4096, "ciphertext too large");
  return h;
}

Bytes header_aad(const WireHeader& h) {
  return encode_header(h);
}

static void put_tlv(Bytes& out, TlvType type, const Bytes& value) {
  put_u16(out, static_cast<std::uint16_t>(type));
  put_u32(out, static_cast<std::uint32_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
}

static Bytes u64_bytes(std::uint64_t v) {
  Bytes out;
  put_u64(out, v);
  return out;
}

static Bytes u32_bytes(std::uint32_t v) {
  Bytes out;
  put_u32(out, v);
  return out;
}

static Bytes u16_bytes(std::uint16_t v) {
  Bytes out;
  put_u16(out, v);
  return out;
}

Bytes encode_tlvs(const Metadata& m) {
  Bytes out;
  put_tlv(out, TlvType::Sha256, Bytes(m.sha.begin(), m.sha.end()));
  put_tlv(out, TlvType::SendMs, u64_bytes(m.send_ms));
  put_tlv(out, TlvType::RoundStartMs, u64_bytes(m.round_start_ms));
  put_tlv(out, TlvType::Sequence, u64_bytes(m.sequence));
  put_tlv(out, TlvType::SourceDevice, string_as_bytes(m.source_device));
  put_tlv(out, TlvType::SourceIp, string_as_bytes(m.source_ip));
  put_tlv(out, TlvType::DestinationIp, string_as_bytes(m.destination_ip));
  put_tlv(out, TlvType::DestinationPort, u16_bytes(m.destination_port));
  put_tlv(out, TlvType::IpProtocol, Bytes{m.ip_protocol});
  put_tlv(out, TlvType::PacketLength, u32_bytes(m.packet_length));
  for (const auto& [type, value] : m.unknown_tlvs) {
    put_u16(out, type);
    put_u32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
  }
  return out;
}

Metadata decode_tlvs(const Bytes& data) {
  Metadata m;
  std::size_t pos = 0;
  while (pos + 6 <= data.size()) {
    const auto type = get_u16(data.data() + pos);
    const auto len = get_u32(data.data() + pos + 2);
    pos += 6;
    require(pos + len <= data.size(), "truncated metadata tlv");
    Bytes value(data.begin() + pos, data.begin() + pos + len);
    pos += len;
    switch (static_cast<TlvType>(type)) {
      case TlvType::Sha256:
        require(value.size() == 32, "bad sha tlv size");
        std::copy(value.begin(), value.end(), m.sha.begin());
        break;
      case TlvType::SendMs:
        require(value.size() == 8, "bad send_ms tlv size");
        m.send_ms = get_u64(value.data());
        break;
      case TlvType::RoundStartMs:
        require(value.size() == 8, "bad round_start_ms tlv size");
        m.round_start_ms = get_u64(value.data());
        break;
      case TlvType::Sequence:
        require(value.size() == 8, "bad sequence tlv size");
        m.sequence = get_u64(value.data());
        break;
      case TlvType::SourceDevice:
        m.source_device = bytes_as_string(value);
        break;
      case TlvType::SourceIp:
        m.source_ip = bytes_as_string(value);
        break;
      case TlvType::DestinationIp:
        m.destination_ip = bytes_as_string(value);
        break;
      case TlvType::DestinationPort:
        require(value.size() == 2, "bad destination port tlv size");
        m.destination_port = get_u16(value.data());
        break;
      case TlvType::IpProtocol:
        require(value.size() == 1, "bad ip protocol tlv size");
        m.ip_protocol = value[0];
        break;
      case TlvType::PacketLength:
        require(value.size() == 4, "bad packet length tlv size");
        m.packet_length = get_u32(value.data());
        break;
      default:
        m.unknown_tlvs[type] = std::move(value);
        break;
    }
  }
  require(pos == data.size(), "trailing partial tlv");
  return m;
}

Bytes make_plaintext(const Metadata& m, const Bytes& packet) {
  Bytes meta = encode_tlvs(m);
  Bytes out;
  put_u32(out, static_cast<std::uint32_t>(meta.size()));
  out.insert(out.end(), meta.begin(), meta.end());
  out.insert(out.end(), packet.begin(), packet.end());
  return out;
}

std::pair<Metadata, Bytes> split_plaintext(const Bytes& plaintext) {
  require(plaintext.size() >= 4, "short plaintext");
  auto meta_len = get_u32(plaintext.data());
  require(4 + meta_len <= plaintext.size(), "metadata length exceeds plaintext");
  Bytes meta_bytes(plaintext.begin() + 4, plaintext.begin() + 4 + meta_len);
  Bytes packet(plaintext.begin() + 4 + meta_len, plaintext.end());
  return {decode_tlvs(meta_bytes), packet};
}

PacketInfo inspect_ip_packet(const Bytes& packet) {
  PacketInfo info;
  if (packet.size() < 20) return info;
  const std::uint8_t version = packet[0] >> 4;
  if (version == 4) {
    const std::size_t ihl = (packet[0] & 0x0f) * 4;
    if (packet.size() < ihl + 4 || ihl < 20) return info;
    char ip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, packet.data() + 12, ip, sizeof(ip));
    info.source_ip = ip;
    inet_ntop(AF_INET, packet.data() + 16, ip, sizeof(ip));
    info.destination_ip = ip;
    info.ip_protocol = packet[9];
    if ((info.ip_protocol == 6 || info.ip_protocol == 17) && packet.size() >= ihl + 4) {
      info.destination_port = get_u16(packet.data() + ihl + 2);
    }
  } else if (version == 6 && packet.size() >= 40) {
    char ip[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, packet.data() + 8, ip, sizeof(ip));
    info.source_ip = ip;
    inet_ntop(AF_INET6, packet.data() + 24, ip, sizeof(ip));
    info.destination_ip = ip;
    info.ip_protocol = packet[6];
    if ((info.ip_protocol == 6 || info.ip_protocol == 17) && packet.size() >= 44) {
      info.destination_port = get_u16(packet.data() + 42);
    }
  }
  return info;
}

std::string packet_type_name(PacketType t) {
  switch (t) {
    case PacketType::Data:
      return "data";
    case PacketType::LogChunk:
      return "log_chunk";
    case PacketType::LogDone:
      return "log_done";
  }
  return "unknown";
}

}  // namespace wiremark
