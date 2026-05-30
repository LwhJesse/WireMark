#include "wiremark/compact.hpp"

#include "wiremark/crypto.hpp"
#include "wiremark/protocol.hpp"

#include <algorithm>

namespace wiremark {

Bytes make_tag_input(std::uint64_t sequence, const Bytes& packet) {
  Bytes out;
  put_u64(out, sequence);
  out.insert(out.end(), packet.begin(), packet.end());
  return out;
}

std::array<std::uint8_t, kTag12Size> tag12(const std::array<std::uint8_t, 32>& key,
                                           std::uint64_t sequence,
                                           const Bytes& packet) {
  const auto h = hmac_sha256(key, make_tag_input(sequence, packet));
  std::array<std::uint8_t, kTag12Size> out{};
  std::copy_n(h.begin(), out.size(), out.begin());
  return out;
}

Bytes encode_compact_batch(std::uint64_t base_sequence, const std::vector<CompactPacket>& packets) {
  Bytes out;
  put_varint(out, base_sequence);
  put_varint(out, packets.size());
  for (const auto& p : packets) {
    put_varint(out, p.packet.size());
    out.insert(out.end(), p.tag.begin(), p.tag.end());
    out.insert(out.end(), p.packet.begin(), p.packet.end());
  }
  return out;
}

std::vector<CompactPacket> decode_compact_batch(const Bytes& plaintext) {
  std::size_t pos = 0;
  const auto base_sequence = get_varint(plaintext, pos);
  const auto count = get_varint(plaintext, pos);
  require(count <= 1024, "compact batch has too many packets");
  std::vector<CompactPacket> packets;
  packets.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t i = 0; i < count; ++i) {
    const auto len = get_varint(plaintext, pos);
    require(len <= kMaxPacketSize, "compact packet too large");
    require(pos + kTag12Size + len <= plaintext.size(), "truncated compact packet");
    CompactPacket p;
    p.sequence = base_sequence + i;
    std::copy_n(plaintext.data() + pos, p.tag.size(), p.tag.begin());
    pos += p.tag.size();
    p.packet.assign(plaintext.begin() + pos, plaintext.begin() + pos + len);
    pos += static_cast<std::size_t>(len);
    packets.push_back(std::move(p));
  }
  require(pos == plaintext.size(), "trailing bytes in compact batch");
  return packets;
}

}  // namespace wiremark
