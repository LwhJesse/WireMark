#include "wiremark/nfq_gateway.hpp"

#include <stdexcept>

namespace wiremark {

void run_nfq_gateway(const NfqGatewayConfig&, Logger&) {
  throw std::runtime_error(
      "nfq mode was not built because libnetfilter_queue headers/libraries were not found. "
      "Install libnetfilter-queue development files and rebuild.");
}

}  // namespace wiremark
