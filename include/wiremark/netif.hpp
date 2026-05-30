#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wiremark {

enum class InterfaceLayer {
  Loopback,
  Tunnel,
  Container,
  Bridge,
  VirtualNic,
  HardwareNic,
  Other,
};

struct InterfaceInfo {
  std::string name;
  InterfaceLayer layer{InterfaceLayer::Other};
  bool up{false};
  bool lower_up{false};
  int arphrd_type{0};
  std::string sysfs_path;
  std::string driver;
  std::string reason;
  int score{0};
};

std::string interface_layer_name(InterfaceLayer layer);
std::vector<InterfaceInfo> list_interfaces();
std::optional<std::string> default_ipv4_interface();
std::optional<InterfaceInfo> choose_lowest_interface(const std::string& peer_ip = "");
void print_interface_plan(const std::string& peer_ip = "");

}  // namespace wiremark
