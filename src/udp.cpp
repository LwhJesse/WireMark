#include "wiremark/udp.hpp"

#include "wiremark/protocol.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace wiremark {

Endpoint parse_endpoint(const std::string& text) {
  if (text == "auto") return Endpoint{"", 0, true};
  const auto pos = text.rfind(':');
  require(pos != std::string::npos, "endpoint must be host:port: " + text);
  const auto port_text = text.substr(pos + 1);
  std::size_t port_pos = 0;
  const auto port_ul = std::stoul(port_text, &port_pos);
  require(port_pos == port_text.size() && port_ul > 0 && port_ul <= 65535,
          "endpoint port out of range: " + text);
  Endpoint e{text.substr(0, pos), static_cast<std::uint16_t>(port_ul)};
  if (e.host.empty()) e.host = "0.0.0.0";
  return e;
}

static sockaddr_storage resolve(const Endpoint& e, int flags, socklen_t* len_out) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = flags;
  addrinfo* result = nullptr;
  const auto port = std::to_string(e.port);
  const int rc = ::getaddrinfo(e.host.c_str(), port.c_str(), &hints, &result);
  require(rc == 0, "getaddrinfo failed for " + e.host + ": " + gai_strerror(rc));
  sockaddr_storage out{};
  std::memcpy(&out, result->ai_addr, result->ai_addrlen);
  *len_out = static_cast<socklen_t>(result->ai_addrlen);
  ::freeaddrinfo(result);
  return out;
}

static Endpoint endpoint_from_sockaddr(const sockaddr_storage& addr) {
  char host[INET6_ADDRSTRLEN]{};
  std::uint16_t port = 0;
  if (addr.ss_family == AF_INET) {
    const auto* in = reinterpret_cast<const sockaddr_in*>(&addr);
    ::inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
    port = ntohs(in->sin_port);
  } else if (addr.ss_family == AF_INET6) {
    const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
    ::inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
    port = ntohs(in6->sin6_port);
  } else {
    throw std::runtime_error("unsupported udp sender address family");
  }
  return Endpoint{host, port, false};
}

UdpSocket::UdpSocket(const Endpoint& listen, const Endpoint& peer) {
  socklen_t listen_len = 0;
  sockaddr_storage listen_addr = resolve(listen, AI_PASSIVE, &listen_len);
  fd_ = ::socket(listen_addr.ss_family, SOCK_DGRAM, 0);
  require(fd_ >= 0, std::string("socket failed: ") + std::strerror(errno));

  int yes = 1;
  ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  if (::bind(fd_, reinterpret_cast<sockaddr*>(&listen_addr), listen_len) < 0) {
    const std::string err = std::strerror(errno);
    ::close(fd_);
    fd_ = -1;
    throw std::runtime_error("bind failed: " + err);
  }

  if (!peer.auto_peer) peer_ = resolve(peer, 0, &peer_len_);
}

UdpSocket::~UdpSocket() {
  if (fd_ >= 0) ::close(fd_);
}

void UdpSocket::send(const Bytes& data) {
  require(peer_len_ != 0, "udp peer is not known yet");
  const auto n = ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&peer_), peer_len_);
  if (n < 0 || static_cast<std::size_t>(n) != data.size()) {
    throw std::runtime_error(std::string("udp send failed: ") + std::strerror(errno));
  }
}

void UdpSocket::set_peer(const Endpoint& peer) {
  require(!peer.auto_peer, "cannot set udp peer from auto endpoint");
  peer_ = resolve(peer, 0, &peer_len_);
}

Bytes UdpSocket::recv() {
  return recv_from(nullptr);
}

Bytes UdpSocket::recv_from(Endpoint* sender) {
  Bytes buf(kMaxPacketSize + 4096);
  sockaddr_storage sender_addr{};
  socklen_t sender_len = sizeof(sender_addr);
  const auto n = ::recvfrom(fd_, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&sender_addr), &sender_len);
  if (n < 0) throw std::runtime_error(std::string("udp recv failed: ") + std::strerror(errno));
  if (sender != nullptr) *sender = endpoint_from_sockaddr(sender_addr);
  buf.resize(static_cast<std::size_t>(n));
  return buf;
}

}  // namespace wiremark
