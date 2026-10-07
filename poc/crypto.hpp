#pragma once

#include <botan/aead.h>
#include <botan/secmem.h>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace filecrypt::poc {
using Bytes = std::vector<std::uint8_t>;
using SecureBytes = Botan::secure_vector<std::uint8_t>;
enum class Algorithm { aes256_gcm, xchacha20_poly1305 };

constexpr std::uint64_t message_limit(Algorithm algorithm) {
    return algorithm == Algorithm::aes256_gcm
        ? (std::uint64_t{1} << 36) - 32
        : (std::uint64_t{1} << 38) - 64;
}

// Counts AEAD input, i.e. compressed bytes when compression is enabled.
class MessageBudget {
public:
    explicit MessageBudget(Algorithm algorithm) : limit_(message_limit(algorithm)) {}
    void consume(std::uint64_t size);
    std::uint64_t used() const { return used_; }
private:
    std::uint64_t limit_;
    std::uint64_t used_{};
};

struct Encrypted {
    Bytes ciphertext;
    Bytes tag;
};

// PoC only: no file format, file IO, compression, or committed plaintext output.
class Cipher {
public:
    Cipher(Algorithm algorithm, bool encrypt, std::span<const std::uint8_t> key,
           std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> aad);
    Bytes update(std::span<const std::uint8_t> input);
    // Encryption returns the final ciphertext and detached tag. Decryption
    // returns the final plaintext only after verifying the supplied tag.
    Encrypted finish(std::span<const std::uint8_t> tag = {});
private:
    std::unique_ptr<Botan::AEAD_Mode> mode_;
    MessageBudget budget_;
    SecureBytes pending_;
    bool encrypt_;
    bool finished_{};
};

SecureBytes derive_key(std::span<const std::uint8_t> password,
                       std::span<const std::uint8_t> salt);
Bytes random_bytes(std::size_t size);
}
