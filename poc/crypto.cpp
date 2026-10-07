#include "crypto.hpp"
#include <botan/auto_rng.h>
#include <botan/pwdhash.h>
#include <stdexcept>

namespace filecrypt::poc {
void MessageBudget::consume(std::uint64_t size) {
    if(size > limit_ - used_) {
        throw std::length_error("File too large for selected AEAD");
    }
    used_ += size;
}

Cipher::Cipher(Algorithm algorithm, bool encrypt, std::span<const std::uint8_t> key,
               std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> aad)
    : mode_(Botan::AEAD_Mode::create_or_throw(
          algorithm == Algorithm::aes256_gcm ? "AES-256/GCM" : "ChaCha20Poly1305",
          encrypt ? Botan::Cipher_Dir::Encryption : Botan::Cipher_Dir::Decryption)),
      budget_(algorithm), encrypt_(encrypt) {
    if(key.size() != 32 || nonce.size() !=
       (algorithm == Algorithm::aes256_gcm ? 12u : 24u)) {
        throw std::invalid_argument("Invalid key or nonce size");
    }
    mode_->set_key(key.data(), key.size());
    mode_->set_associated_data(aad.data(), aad.size());
    mode_->start(nonce.data(), nonce.size());
}

Bytes Cipher::update(std::span<const std::uint8_t> input) {
    if(finished_) { throw std::logic_error("Cipher already finalized"); }
    budget_.consume(input.size());
    pending_.insert(pending_.end(), input.begin(), input.end());
    const auto size = pending_.size() / mode_->update_granularity() * mode_->update_granularity();
    if(size == 0) { return {}; }
    const auto written = mode_->process(pending_.data(), size);
    Bytes output(pending_.begin(), pending_.begin() + written);
    pending_.erase(pending_.begin(), pending_.begin() + size);
    return output;
}

Encrypted Cipher::finish(std::span<const std::uint8_t> tag) {
    if(finished_) { throw std::logic_error("Cipher already finalized"); }
    if((encrypt_ && !tag.empty()) || (!encrypt_ && tag.size() != mode_->tag_size())) {
        throw std::invalid_argument("Invalid authentication tag size");
    }
    finished_ = true;
    if(!encrypt_) { pending_.insert(pending_.end(), tag.begin(), tag.end()); }
    mode_->finish(pending_);
    Encrypted result;
    if(encrypt_) {
        const auto tag_start = pending_.end() - mode_->tag_size();
        result.ciphertext.assign(pending_.begin(), tag_start);
        result.tag.assign(tag_start, pending_.end());
    } else {
        result.ciphertext.assign(pending_.begin(), pending_.end());
    }
    pending_.clear();
    return result;
}

SecureBytes derive_key(std::span<const std::uint8_t> password,
                       std::span<const std::uint8_t> salt) {
    auto family = Botan::PasswordHashFamily::create_or_throw("Argon2id");
    // Explicit, fast PoC parameters: 8 MiB, one iteration, one lane.
    // These are NOT production password-hardening defaults.
    auto parameters = family->from_params(8192, 1, 1);
    SecureBytes key(32);
    parameters->derive_key(key.data(), key.size(),
        reinterpret_cast<const char*>(password.data()), password.size(),
        salt.data(), salt.size());
    return key;
}

Bytes random_bytes(std::size_t size) {
    Botan::AutoSeeded_RNG rng;
    Bytes result(size);
    rng.randomize(result.data(), result.size());
    return result;
}
}
