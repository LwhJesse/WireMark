#pragma once

#include "wiremark/logger.hpp"
#include "wiremark/udp.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>

namespace wiremark {

enum class PacketPolicy {
  Drop,
  Accept,
};

PacketPolicy parse_packet_policy(const std::string& value);
std::string packet_policy_name(PacketPolicy policy);

struct NfqGatewayConfig {
  std::uint16_t queue_num{70};
  Endpoint listen{"0.0.0.0", 47000};
  Endpoint peer{"127.0.0.1", 47000};
  std::string device_id{"wiremark-nfq"};
  std::string key_file;
  std::filesystem::path quarantine_dir;
  std::uint16_t wrapper_mtu{1200};
  bool fail_closed{true};
  PacketPolicy invalid_policy{PacketPolicy::Drop};
  PacketPolicy replay_policy{PacketPolicy::Drop};
};

void run_nfq_gateway(const NfqGatewayConfig& cfg, Logger& logger);

}  // namespace wiremark
