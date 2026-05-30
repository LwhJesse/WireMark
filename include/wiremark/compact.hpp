#pragma once

#include "wiremark/util.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace wiremark {

constexpr std::size_t kTag12Size = 12;

struct CompactPacket {
  std::uint64_t sequence{0};
  std::array<std::uint8_t, kTag12Size> tag{};
  Bytes packet;
};

Bytes make_tag_input(std::uint64_t sequence, const Bytes& packet);
std::array<std::uint8_t, kTag12Size> tag12(const std::array<std::uint8_t, 32>& key,
                                           std::uint64_t sequence,
                                           const Bytes& packet);

Bytes encode_compact_batch(std::uint64_t base_sequence, const std::vector<CompactPacket>& packets);
std::vector<CompactPacket> decode_compact_batch(const Bytes& plaintext);

}  // namespace wiremark
