#pragma once

#include "wiremark/logger.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace wiremark {

struct CaptureConfig {
  std::string iface;
  std::string peer_ip;
  std::uint16_t port{443};
  std::uint64_t seconds{30};
  bool payload_only{false};
};

void capture_udp(const CaptureConfig& cfg, Logger& logger);

}  // namespace wiremark
