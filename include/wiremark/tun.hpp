#pragma once

#include "wiremark/util.hpp"

#include <string>

namespace wiremark {

class TunDevice {
 public:
  explicit TunDevice(const std::string& name);
  ~TunDevice();
  TunDevice(const TunDevice&) = delete;
  TunDevice& operator=(const TunDevice&) = delete;

  int fd() const { return fd_; }
  const std::string& name() const { return name_; }
  Bytes read_packet();
  void write_packet(const Bytes& packet);

 private:
  int fd_{-1};
  std::string name_;
};

}  // namespace wiremark
