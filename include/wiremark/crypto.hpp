#pragma once

#include "wiremark/util.hpp"

#include <array>
#include <string>

namespace wiremark {

struct KeyMaterial {
  std::array<std::uint8_t, 32> data_key{};
  std::array<std::uint8_t, 32> control_key{};
  std::array<std::uint8_t, 32> integrity_key{};
};

std::array<std::uint8_t, 32> sha256(const Bytes& data);
std::array<std::uint8_t, 32> hmac_sha256(const std::array<std::uint8_t, 32>& key, const Bytes& data);
std::string hex(const std::uint8_t* data, std::size_t len);
std::string hex(const std::array<std::uint8_t, 32>& data);
Bytes random_bytes(std::size_t len);
Bytes read_key_file(const std::string& path);
KeyMaterial derive_keys(const Bytes& secret, const std::string& context);

Bytes aes256gcm_encrypt(const std::array<std::uint8_t, 32>& key,
                        const std::array<std::uint8_t, 12>& nonce,
                        const Bytes& plaintext,
                        const Bytes& aad);

Bytes aes256gcm_decrypt(const std::array<std::uint8_t, 32>& key,
                        const std::array<std::uint8_t, 12>& nonce,
                        const Bytes& ciphertext_and_tag,
                        const Bytes& aad);

}  // namespace wiremark
