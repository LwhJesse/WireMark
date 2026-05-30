#pragma once

#include "wiremark/udp.hpp"
#include "wiremark/util.hpp"

namespace wiremark {

class TcpStream {
 public:
  static TcpStream connect_to(const Endpoint& endpoint);
  static TcpStream listen_one(const Endpoint& endpoint);
  ~TcpStream();
  TcpStream(TcpStream&& other) noexcept;
  TcpStream& operator=(TcpStream&& other) noexcept;
  TcpStream(const TcpStream&) = delete;
  TcpStream& operator=(const TcpStream&) = delete;

  int fd() const { return fd_; }
  void send_frame(const Bytes& frame);
  Bytes recv_frame();

 private:
  explicit TcpStream(int fd) : fd_(fd) {}
  int fd_{-1};
};

}  // namespace wiremark
