#include "wiremark/netif.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>

namespace wiremark {

namespace {

std::string read_first_line(const std::filesystem::path& path) {
  std::ifstream in(path);
  std::string s;
  std::getline(in, s);
  return s;
}

bool contains(const std::string& text, const std::string& needle) {
  return text.find(needle) != std::string::npos;
}

bool starts_with(const std::string& text, const std::string& prefix) {
  return text.rfind(prefix, 0) == 0;
}

std::string sysfs_target(const std::filesystem::path& iface) {
  std::error_code ec;
  const auto target = std::filesystem::read_symlink(iface, ec);
  if (ec) return {};
  return target.string();
}

std::string driver_for(const std::string& name) {
  std::error_code ec;
  const auto link = std::filesystem::read_symlink("/sys/class/net/" + name + "/device/driver", ec);
  if (ec) return {};
  return link.filename().string();
}

int read_int_file(const std::filesystem::path& path) {
  std::ifstream in(path);
  int v = 0;
  in >> v;
  return v;
}

InterfaceInfo classify(const std::string& name) {
  InterfaceInfo info;
  info.name = name;
  const std::filesystem::path base = "/sys/class/net/" + name;
  info.arphrd_type = read_int_file(base / "type");
  const auto flags = read_first_line(base / "operstate");
  info.up = flags == "up" || flags == "unknown";
  info.lower_up = flags == "up";
  info.sysfs_path = sysfs_target(base);
  info.driver = driver_for(name);

  const bool is_virtual_path = contains(info.sysfs_path, "/virtual/");
  const bool is_tun_type = info.arphrd_type == 65534;
  const bool is_loopback = info.arphrd_type == 772 || name == "lo";
  const bool is_container = starts_with(name, "veth") || starts_with(name, "docker") ||
                            starts_with(name, "br-");
  const bool is_bridge = name == "docker0" || starts_with(name, "br") || contains(info.driver, "bridge");
  const bool looks_tunnel = is_tun_type || contains(name, "tun") || contains(name, "tap") ||
                            contains(name, "tailscale") || contains(name, "wg") ||
                            contains(name, "neko");

  if (is_loopback) {
    info.layer = InterfaceLayer::Loopback;
    info.score = -1000;
    info.reason = "loopback";
  } else if (looks_tunnel) {
    info.layer = InterfaceLayer::Tunnel;
    info.score = 20;
    info.reason = "tunnel/point-to-point virtual interface";
  } else if (is_container) {
    info.layer = InterfaceLayer::Container;
    info.score = 30;
    info.reason = "container/namespace interface";
  } else if (is_bridge) {
    info.layer = InterfaceLayer::Bridge;
    info.score = 35;
    info.reason = "software bridge";
  } else if (info.arphrd_type == 1 && !is_virtual_path) {
    info.layer = contains(info.sysfs_path, "virtio") || contains(info.driver, "virtio")
                     ? InterfaceLayer::VirtualNic
                     : InterfaceLayer::HardwareNic;
    info.score = info.layer == InterfaceLayer::HardwareNic ? 100 : 90;
    info.reason = info.layer == InterfaceLayer::HardwareNic ? "kernel-visible hardware NIC"
                                                             : "cloud/VM virtio NIC";
  } else if (info.arphrd_type == 1) {
    info.layer = InterfaceLayer::VirtualNic;
    info.score = 60;
    info.reason = "kernel-visible virtual ethernet";
  } else {
    info.layer = InterfaceLayer::Other;
    info.score = 10;
    info.reason = "unclassified interface";
  }

  if (!info.up) info.score -= 40;
  return info;
}

std::optional<std::string> route_iface_for_ipv4(const std::string& peer_ip) {
  if (peer_ip.empty()) return std::nullopt;
  in_addr target{};
  if (::inet_pton(AF_INET, peer_ip.c_str(), &target) != 1) return std::nullopt;
  const std::uint32_t dst = ntohl(target.s_addr);

  std::ifstream in("/proc/net/route");
  std::string line;
  std::getline(in, line);
  std::string best_iface;
  int best_prefix = -1;
  while (std::getline(in, line)) {
    std::istringstream ss(line);
    std::string iface, dest_hex, gateway_hex, flags_hex, refcnt, use, metric, mask_hex;
    ss >> iface >> dest_hex >> gateway_hex >> flags_hex >> refcnt >> use >> metric >> mask_hex;
    if (iface.empty() || dest_hex.empty() || mask_hex.empty()) continue;
    const std::uint32_t dest_le = static_cast<std::uint32_t>(std::stoul(dest_hex, nullptr, 16));
    const std::uint32_t mask_le = static_cast<std::uint32_t>(std::stoul(mask_hex, nullptr, 16));
    const std::uint32_t dest_net = ntohl(dest_le);
    const std::uint32_t mask = ntohl(mask_le);
    if ((dst & mask) != (dest_net & mask)) continue;
    const int prefix = __builtin_popcount(mask);
    if (prefix > best_prefix) {
      best_prefix = prefix;
      best_iface = iface;
    }
  }
  if (best_iface.empty()) return std::nullopt;
  return best_iface;
}

}  // namespace

std::string interface_layer_name(InterfaceLayer layer) {
  switch (layer) {
    case InterfaceLayer::Loopback:
      return "loopback";
    case InterfaceLayer::Tunnel:
      return "tunnel";
    case InterfaceLayer::Container:
      return "container";
    case InterfaceLayer::Bridge:
      return "bridge";
    case InterfaceLayer::VirtualNic:
      return "virtual-nic";
    case InterfaceLayer::HardwareNic:
      return "hardware-nic";
    case InterfaceLayer::Other:
      return "other";
  }
  return "other";
}

std::vector<InterfaceInfo> list_interfaces() {
  std::vector<InterfaceInfo> out;
  const std::filesystem::path root = "/sys/class/net";
  std::error_code ec;
  for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
    if (ec) break;
    out.push_back(classify(entry.path().filename().string()));
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    if (a.score != b.score) return a.score > b.score;
    return a.name < b.name;
  });
  return out;
}

std::optional<std::string> default_ipv4_interface() {
  std::ifstream in("/proc/net/route");
  std::string line;
  std::getline(in, line);
  while (std::getline(in, line)) {
    std::istringstream ss(line);
    std::string iface, dest;
    ss >> iface >> dest;
    if (dest == "00000000") return iface;
  }
  return std::nullopt;
}

std::optional<InterfaceInfo> choose_lowest_interface(const std::string& peer_ip) {
  auto interfaces = list_interfaces();
  const auto route_iface = route_iface_for_ipv4(peer_ip).value_or(default_ipv4_interface().value_or(""));
  for (auto& iface : interfaces) {
    if (!route_iface.empty() && iface.name == route_iface) iface.score += 1000;
  }
  std::sort(interfaces.begin(), interfaces.end(), [](const auto& a, const auto& b) {
    if (a.score != b.score) return a.score > b.score;
    return a.name < b.name;
  });
  for (const auto& iface : interfaces) {
    if (iface.layer == InterfaceLayer::Loopback || iface.layer == InterfaceLayer::Tunnel ||
        iface.layer == InterfaceLayer::Container || iface.layer == InterfaceLayer::Bridge) {
      continue;
    }
    if (iface.up) return iface;
  }
  for (const auto& iface : interfaces) {
    if (iface.layer != InterfaceLayer::Loopback && iface.up) return iface;
  }
  return std::nullopt;
}

void print_interface_plan(const std::string& peer_ip) {
  const auto chosen = choose_lowest_interface(peer_ip);
  const auto route_iface = route_iface_for_ipv4(peer_ip).value_or(default_ipv4_interface().value_or(""));
  std::cout << "WireMark interface plan\n";
  if (!peer_ip.empty()) std::cout << "peer_ip=" << peer_ip << "\n";
  if (!route_iface.empty()) std::cout << "route_iface=" << route_iface << "\n";
  if (chosen) {
    std::cout << "selected=" << chosen->name << " layer=" << interface_layer_name(chosen->layer)
              << " driver=" << chosen->driver << " reason=" << chosen->reason << "\n";
  } else {
    std::cout << "selected=<none>\n";
  }
  for (const auto& iface : list_interfaces()) {
    std::cout << iface.name << "\t" << interface_layer_name(iface.layer) << "\t"
              << "up=" << (iface.up ? "yes" : "no") << "\t"
              << "driver=" << (iface.driver.empty() ? "-" : iface.driver) << "\t"
              << iface.reason << "\n";
  }
}

}  // namespace wiremark
