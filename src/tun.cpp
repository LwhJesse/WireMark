#include "wiremark/tun.hpp"

#include "wiremark/protocol.hpp"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace wiremark {

TunDevice::TunDevice(const std::string& name) : name_(name) {
  fd_ = ::open("/dev/net/tun", O_RDWR);
  require(fd_ >= 0, std::string("open /dev/net/tun failed: ") + std::strerror(errno));

  ifreq ifr{};
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name.c_str());
  if (::ioctl(fd_, TUNSETIFF, &ifr) < 0) {
    const std::string err = std::strerror(errno);
    ::close(fd_);
    fd_ = -1;
    throw std::runtime_error("TUNSETIFF failed: " + err);
  }
  name_ = ifr.ifr_name;
}

TunDevice::~TunDevice() {
  if (fd_ >= 0) ::close(fd_);
}

Bytes TunDevice::read_packet() {
  Bytes buf(kMaxPacketSize);
  const auto n = ::read(fd_, buf.data(), buf.size());
  if (n < 0) throw std::runtime_error(std::string("tun read failed: ") + std::strerror(errno));
  buf.resize(static_cast<std::size_t>(n));
  return buf;
}

void TunDevice::write_packet(const Bytes& packet) {
  std::size_t off = 0;
  while (off < packet.size()) {
    const auto n = ::write(fd_, packet.data() + off, packet.size() - off);
    if (n < 0) throw std::runtime_error(std::string("tun write failed: ") + std::strerror(errno));
    off += static_cast<std::size_t>(n);
  }
}

}  // namespace wiremark
