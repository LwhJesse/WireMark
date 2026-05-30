#include "wiremark/nfq_gateway.hpp"

#include <stdexcept>

namespace wiremark {

PacketPolicy parse_packet_policy(const std::string& value) {
  if (value == "drop") return PacketPolicy::Drop;
  if (value == "accept") return PacketPolicy::Accept;
  throw std::runtime_error("packet policy must be drop or accept: " + value);
}

std::string packet_policy_name(PacketPolicy policy) {
  switch (policy) {
    case PacketPolicy::Drop:
      return "drop";
    case PacketPolicy::Accept:
      return "accept";
  }
  return "drop";
}

}  // namespace wiremark
