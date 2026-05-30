#pragma once

#include "wiremark/util.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace wiremark {

constexpr std::uint32_t kMagic = 0x574d4b31;  // WMK1
constexpr std::uint8_t kVersion = 1;
constexpr std::size_t kHeaderSize = 48;
constexpr std::size_t kMaxPacketSize = 65535;

enum class PacketType : std::uint8_t {
  Data = 1,
  LogChunk = 2,
  LogDone = 3,
};

enum class TlvType : std::uint16_t {
  Sha256 = 1,
  SendMs = 2,
  RoundStartMs = 3,
  Sequence = 4,
  SourceDevice = 5,
  DestinationIp = 6,
  DestinationPort = 7,
  IpProtocol = 8,
  PacketLength = 9,
  SourceIp = 10,
  LogName = 20,
  LogData = 21,
};

struct WireHeader {
  PacketType type{PacketType::Data};
  std::uint16_t flags{0};
  std::array<std::uint8_t, 16> session_id{};
  std::uint64_t sequence{0};
  std::array<std::uint8_t, 12> nonce{};
  std::uint32_t ciphertext_len{0};
};

struct PacketInfo {
  std::string source_ip;
  std::string destination_ip;
  std::uint16_t destination_port{0};
  std::uint8_t ip_protocol{0};
};

struct Metadata {
  std::array<std::uint8_t, 32> sha{};
  std::uint64_t send_ms{0};
  std::uint64_t round_start_ms{0};
  std::uint64_t sequence{0};
  std::string source_device;
  std::string source_ip;
  std::string destination_ip;
  std::uint16_t destination_port{0};
  std::uint8_t ip_protocol{0};
  std::uint32_t packet_length{0};
  std::map<std::uint16_t, Bytes> unknown_tlvs;
};

Bytes encode_header(const WireHeader& h);
WireHeader decode_header(const std::uint8_t* data, std::size_t len);
Bytes header_aad(const WireHeader& h);

Bytes encode_tlvs(const Metadata& m);
Metadata decode_tlvs(const Bytes& data);

Bytes make_plaintext(const Metadata& m, const Bytes& packet);
std::pair<Metadata, Bytes> split_plaintext(const Bytes& plaintext);

PacketInfo inspect_ip_packet(const Bytes& packet);
std::string packet_type_name(PacketType t);

}  // namespace wiremark
