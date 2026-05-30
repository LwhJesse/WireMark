#include "wiremark/tcp.hpp"

#include "wiremark/protocol.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace wiremark {

namespace {

sockaddr_storage resolve_one(const Endpoint& e, int flags, socklen_t* len_out) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
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

void read_exact(int fd, std::uint8_t* data, std::size_t len) {
  std::size_t off = 0;
  while (off < len) {
    const auto n = ::read(fd, data + off, len - off);
    if (n == 0) throw std::runtime_error("tcp stream closed");
    if (n < 0) {
      if (errno == EINTR) continue;
      throw std::runtime_error(std::string("tcp read failed: ") + std::strerror(errno));
    }
    off += static_cast<std::size_t>(n);
  }
}

void write_exact(int fd, const std::uint8_t* data, std::size_t len) {
  std::size_t off = 0;
  while (off < len) {
    const auto n = ::write(fd, data + off, len - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      throw std::runtime_error(std::string("tcp write failed: ") + std::strerror(errno));
    }
    off += static_cast<std::size_t>(n);
  }
}

}  // namespace

TcpStream TcpStream::connect_to(const Endpoint& endpoint) {
  socklen_t len = 0;
  auto addr = resolve_one(endpoint, 0, &len);
  const int fd = ::socket(addr.ss_family, SOCK_STREAM, 0);
  require(fd >= 0, std::string("tcp socket failed: ") + std::strerror(errno));
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), len) < 0) {
    const std::string err = std::strerror(errno);
    ::close(fd);
    throw std::runtime_error("tcp connect failed: " + err);
  }
  return TcpStream(fd);
}

TcpStream TcpStream::listen_one(const Endpoint& endpoint) {
  socklen_t len = 0;
  auto addr = resolve_one(endpoint, AI_PASSIVE, &len);
  const int listen_fd = ::socket(addr.ss_family, SOCK_STREAM, 0);
  require(listen_fd >= 0, std::string("tcp socket failed: ") + std::strerror(errno));
  int yes = 1;
  ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), len) < 0) {
    const std::string err = std::strerror(errno);
    ::close(listen_fd);
    throw std::runtime_error("tcp bind failed: " + err);
  }
  require(::listen(listen_fd, 1) == 0, std::string("tcp listen failed: ") + std::strerror(errno));
  const int fd = ::accept(listen_fd, nullptr, nullptr);
  const std::string err = std::strerror(errno);
  ::close(listen_fd);
  require(fd >= 0, "tcp accept failed: " + err);
  return TcpStream(fd);
}

TcpStream::~TcpStream() {
  if (fd_ >= 0) ::close(fd_);
}

TcpStream::TcpStream(TcpStream&& other) noexcept : fd_(other.fd_) {
  other.fd_ = -1;
}

TcpStream& TcpStream::operator=(TcpStream&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) ::close(fd_);
    fd_ = other.fd_;
    other.fd_ = -1;
  }
  return *this;
}

void TcpStream::send_frame(const Bytes& frame) {
  Bytes len;
  put_u32(len, static_cast<std::uint32_t>(frame.size()));
  write_exact(fd_, len.data(), len.size());
  write_exact(fd_, frame.data(), frame.size());
}

Bytes TcpStream::recv_frame() {
  std::array<std::uint8_t, 4> len_buf{};
  read_exact(fd_, len_buf.data(), len_buf.size());
  const auto len = get_u32(len_buf.data());
  require(len <= kMaxPacketSize + 4096, "tcp frame too large");
  Bytes frame(len);
  read_exact(fd_, frame.data(), frame.size());
  return frame;
}

}  // namespace wiremark
