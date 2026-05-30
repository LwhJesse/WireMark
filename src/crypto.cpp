#include "wiremark/crypto.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <fstream>
#include <iomanip>
#include <sstream>

namespace wiremark {

std::array<std::uint8_t, 32> sha256(const Bytes& data) {
  std::array<std::uint8_t, 32> out{};
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  require(ctx != nullptr, "EVP_MD_CTX_new failed");
  require(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1, "sha256 init failed");
  require(EVP_DigestUpdate(ctx, data.data(), data.size()) == 1, "sha256 update failed");
  unsigned int len = 0;
  require(EVP_DigestFinal_ex(ctx, out.data(), &len) == 1 && len == out.size(), "sha256 final failed");
  EVP_MD_CTX_free(ctx);
  return out;
}

std::array<std::uint8_t, 32> hmac_sha256(const std::array<std::uint8_t, 32>& key, const Bytes& data) {
  std::array<std::uint8_t, 32> out{};
  unsigned int len = 0;
  require(HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), out.data(), &len) != nullptr,
          "HMAC-SHA256 failed");
  require(len == out.size(), "unexpected HMAC-SHA256 length");
  return out;
}

std::string hex(const std::uint8_t* data, std::size_t len) {
  std::ostringstream os;
  os << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < len; ++i) os << std::setw(2) << static_cast<int>(data[i]);
  return os.str();
}

std::string hex(const std::array<std::uint8_t, 32>& data) {
  return hex(data.data(), data.size());
}

Bytes random_bytes(std::size_t len) {
  Bytes out(len);
  require(RAND_bytes(out.data(), static_cast<int>(out.size())) == 1, "RAND_bytes failed");
  return out;
}

Bytes read_key_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  require(in.good(), "cannot open key file: " + path);
  Bytes data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  while (!data.empty() && (data.back() == '\n' || data.back() == '\r' || data.back() == ' ')) data.pop_back();
  require(data.size() >= 32, "key file must contain at least 32 bytes/chars of secret material");
  return data;
}

static std::array<std::uint8_t, 32> hkdf_one(const Bytes& secret, const std::string& info) {
  std::array<std::uint8_t, 32> out{};
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  require(pctx != nullptr, "HKDF context allocation failed");
  require(EVP_PKEY_derive_init(pctx) == 1, "HKDF init failed");
  require(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1, "HKDF md failed");
  const std::string salt = "wiremark-v1";
  require(EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const unsigned char*>(salt.data()),
                                      static_cast<int>(salt.size())) == 1,
          "HKDF salt failed");
  require(EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), secret.size()) == 1, "HKDF key failed");
  require(EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(info.data()),
                                      static_cast<int>(info.size())) == 1,
          "HKDF info failed");
  std::size_t len = out.size();
  require(EVP_PKEY_derive(pctx, out.data(), &len) == 1 && len == out.size(), "HKDF derive failed");
  EVP_PKEY_CTX_free(pctx);
  return out;
}

KeyMaterial derive_keys(const Bytes& secret, const std::string& context) {
  return {hkdf_one(secret, "wiremark data " + context), hkdf_one(secret, "wiremark control " + context),
          hkdf_one(secret, "wiremark integrity " + context)};
}

Bytes aes256gcm_encrypt(const std::array<std::uint8_t, 32>& key,
                        const std::array<std::uint8_t, 12>& nonce,
                        const Bytes& plaintext,
                        const Bytes& aad) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  require(ctx != nullptr, "cipher context allocation failed");
  require(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1, "gcm init failed");
  require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1, "gcm ivlen failed");
  require(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1, "gcm key failed");

  int len = 0;
  if (!aad.empty()) require(EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1, "gcm aad failed");
  Bytes out(plaintext.size() + 16);
  require(EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), plaintext.size()) == 1, "gcm encrypt failed");
  int total = len;
  require(EVP_EncryptFinal_ex(ctx, out.data() + total, &len) == 1, "gcm final failed");
  total += len;
  require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + total) == 1, "gcm tag failed");
  out.resize(total + 16);
  EVP_CIPHER_CTX_free(ctx);
  return out;
}

Bytes aes256gcm_decrypt(const std::array<std::uint8_t, 32>& key,
                        const std::array<std::uint8_t, 12>& nonce,
                        const Bytes& ciphertext_and_tag,
                        const Bytes& aad) {
  require(ciphertext_and_tag.size() >= 16, "ciphertext shorter than gcm tag");
  const std::size_t ciphertext_len = ciphertext_and_tag.size() - 16;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  require(ctx != nullptr, "cipher context allocation failed");
  require(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1, "gcm init failed");
  require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1, "gcm ivlen failed");
  require(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1, "gcm key failed");
  int len = 0;
  if (!aad.empty()) require(EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) == 1, "gcm aad failed");
  Bytes out(ciphertext_len);
  require(EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext_and_tag.data(), ciphertext_len) == 1, "gcm decrypt failed");
  int total = len;
  require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                              const_cast<std::uint8_t*>(ciphertext_and_tag.data() + ciphertext_len)) == 1,
          "gcm set tag failed");
  int ok = EVP_DecryptFinal_ex(ctx, out.data() + total, &len);
  EVP_CIPHER_CTX_free(ctx);
  require(ok == 1, "gcm authentication failed");
  out.resize(total + len);
  return out;
}

}  // namespace wiremark
