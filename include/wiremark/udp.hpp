#pragma once

#include "wiremark/util.hpp"

#include <netinet/in.h>
#include <string>

namespace wiremark {

struct Endpoint {
  std::string host;
  std::uint16_t port{0};
  bool auto_peer{false};
};

Endpoint parse_endpoint(const std::string& text);

class UdpSocket {
 public:
  UdpSocket(const Endpoint& listen, const Endpoint& peer);
  ~UdpSocket();
  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;

  int fd() const { return fd_; }
  bool has_peer() const { return peer_len_ != 0; }
  void set_peer(const Endpoint& peer);
  void send(const Bytes& data);
  Bytes recv();
  Bytes recv_from(Endpoint* sender);

 private:
  int fd_{-1};
  sockaddr_storage peer_{};
  socklen_t peer_len_{0};
};

}  // namespace wiremark
