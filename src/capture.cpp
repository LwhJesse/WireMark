#include "wiremark/capture.hpp"

#include "wiremark/crypto.hpp"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace wiremark {

namespace {

std::string ipv4_to_string(const std::uint8_t* p) {
  char buf[INET_ADDRSTRLEN]{};
  ::inet_ntop(AF_INET, p, buf, sizeof(buf));
  return buf;
}

bool ip_matches(const std::string& peer, const std::string& a, const std::string& b) {
  return peer.empty() || peer == a || peer == b;
}

}  // namespace

void capture_udp(const CaptureConfig& cfg, Logger& logger) {
  const int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  require(fd >= 0, std::string("AF_PACKET socket failed: ") + std::strerror(errno));

  sockaddr_ll bind_addr{};
  bind_addr.sll_family = AF_PACKET;
  bind_addr.sll_protocol = htons(ETH_P_ALL);
  bind_addr.sll_ifindex = static_cast<int>(::if_nametoindex(cfg.iface.c_str()));
  if (bind_addr.sll_ifindex == 0) {
    ::close(fd);
    throw std::runtime_error("unknown interface: " + cfg.iface);
  }
  if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
    const std::string err = std::strerror(errno);
    ::close(fd);
    throw std::runtime_error("capture bind failed: " + err);
  }

  logger.event("capture_started", "iface=" + cfg.iface + " port=" + std::to_string(cfg.port));
  const auto stop_at = now_ms() + cfg.seconds * 1000;
  Bytes buf(65536);
  while (now_ms() < stop_at) {
    timeval tv{0, 250000};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    const int rc = ::select(fd + 1, &rfds, nullptr, nullptr, &tv);
    if (rc < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (rc == 0) continue;
    const auto n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0) continue;
    if (n < 14) continue;

    std::size_t eth = 14;
    std::uint16_t ether_type = get_u16(buf.data() + 12);
    if (ether_type == 0x8100 && n >= 18) {
      ether_type = get_u16(buf.data() + 16);
      eth = 18;
    }
    if (ether_type != ETH_P_IP || static_cast<std::size_t>(n) < eth + 20) continue;

    const std::uint8_t* ip = buf.data() + eth;
    const std::uint8_t version = ip[0] >> 4;
    const std::size_t ihl = (ip[0] & 0x0f) * 4;
    if (version != 4 || ihl < 20 || static_cast<std::size_t>(n) < eth + ihl + 8) continue;
    if (ip[9] != 17) continue;

    const std::uint16_t total_len = get_u16(ip + 2);
    if (total_len < ihl + 8 || eth + total_len > static_cast<std::size_t>(n)) continue;
    const std::uint8_t* udp = ip + ihl;
    const auto src_port = get_u16(udp);
    const auto dst_port = get_u16(udp + 2);
    if (src_port != cfg.port && dst_port != cfg.port) continue;

    const auto src_ip = ipv4_to_string(ip + 12);
    const auto dst_ip = ipv4_to_string(ip + 16);
    if (!ip_matches(cfg.peer_ip, src_ip, dst_ip)) continue;

    const std::uint8_t* hash_start = cfg.payload_only ? udp + 8 : ip;
    std::size_t hash_len = cfg.payload_only ? total_len - ihl - 8 : total_len;
    Bytes material(hash_start, hash_start + hash_len);

    CaptureRecord r;
    r.ms = now_ms();
    r.direction = dst_port == cfg.port ? "to_server" : "from_server";
    r.src_ip = src_ip;
    r.dst_ip = dst_ip;
    r.src_port = src_port;
    r.dst_port = dst_port;
    r.length = static_cast<std::uint32_t>(total_len);
    r.sha256_hex = hex(sha256(material));
    logger.capture(r);
  }
  logger.event("capture_stopped", "done");
  ::close(fd);
}

}  // namespace wiremark
