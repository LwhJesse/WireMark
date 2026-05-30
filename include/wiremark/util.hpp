#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace wiremark {

using Bytes = std::vector<std::uint8_t>;

inline std::uint64_t now_ms() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

inline void put_u16(Bytes& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

inline void put_u32(Bytes& out, std::uint32_t v) {
  for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

inline void put_u64(Bytes& out, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}

inline void put_varint(Bytes& out, std::uint64_t v) {
  while (v >= 0x80) {
    out.push_back(static_cast<std::uint8_t>(v) | 0x80);
    v >>= 7;
  }
  out.push_back(static_cast<std::uint8_t>(v));
}

inline std::uint64_t get_varint(const Bytes& data, std::size_t& pos) {
  std::uint64_t v = 0;
  int shift = 0;
  while (pos < data.size()) {
    const auto b = data[pos++];
    v |= static_cast<std::uint64_t>(b & 0x7f) << shift;
    if ((b & 0x80) == 0) return v;
    shift += 7;
    if (shift > 63) break;
  }
  throw std::runtime_error("bad varint");
}

inline std::uint16_t get_u16(const std::uint8_t* p) {
  return (static_cast<std::uint16_t>(p[0]) << 8) | p[1];
}

inline std::uint32_t get_u32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}

inline std::uint64_t get_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}

inline std::string bytes_as_string(const Bytes& b) {
  return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

inline Bytes string_as_bytes(const std::string& s) {
  return Bytes(s.begin(), s.end());
}

inline void require(bool ok, const std::string& message) {
  if (!ok) throw std::runtime_error(message);
}

}  // namespace wiremark
