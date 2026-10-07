#include "crypto.hpp"
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/version.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

using namespace filecrypt::poc;

void check(bool condition, const char* message) {
    if(!condition) { throw std::runtime_error(message); }
}
template<class Error, class Function>
void rejects(Function function) {
    try { function(); }
    catch(const Error&) { return; }
    throw std::runtime_error("Expected error was not raised");
}
void append(Bytes& output, const Bytes& part) {
    output.insert(output.end(), part.begin(), part.end());
}
Encrypted encrypt(Algorithm algorithm, std::span<const std::uint8_t> key,
                  const Bytes& nonce, const Bytes& aad, const Bytes& input, std::size_t chunk) {
    Cipher cipher(algorithm, true, key, nonce, aad);
    Encrypted output;
    for(std::size_t offset = 0; offset < input.size(); offset += chunk) {
        append(output.ciphertext, cipher.update(std::span(input).subspan(
            offset, std::min(chunk, input.size() - offset))));
    }
    auto tail = cipher.finish();
    append(output.ciphertext, tail.ciphertext);
    output.tag = tail.tag;
    rejects<std::logic_error>([&] { cipher.update({}); });
    rejects<std::logic_error>([&] { cipher.finish(); });
    return output;
}
Bytes decrypt(Algorithm algorithm, std::span<const std::uint8_t> key,
              const Bytes& nonce, const Bytes& aad, const Encrypted& input, std::size_t chunk) {
    Cipher cipher(algorithm, false, key, nonce, aad);
    // Unauthenticated plaintext is private until finish succeeds.
    Bytes staging;
    for(std::size_t offset = 0; offset < input.ciphertext.size(); offset += chunk) {
        append(staging, cipher.update(std::span(input.ciphertext).subspan(
            offset, std::min(chunk, input.ciphertext.size() - offset))));
    }
    append(staging, cipher.finish(input.tag).ciphertext);
    return staging;
}

void vectors() {
    const Bytes key(32, 0);
    // AES-256-GCM zero-key/zero-IV vector, NIST GCM examples.
    auto aes = encrypt(Algorithm::aes256_gcm, key, Bytes(12, 0), {}, Bytes(16, 0), 1);
    check(aes.ciphertext == Botan::hex_decode("cea7403d4d606b6e074ec5d3baf39d18"), "AES vector ciphertext");
    check(aes.tag == Botan::hex_decode("d0d1c8a799996bf0265b98b5d48ab919"), "AES vector tag");
    check(decrypt(Algorithm::aes256_gcm, key, Bytes(12, 0), {}, aes, 3) == Bytes(16, 0), "AES vector decrypt");
    // Botan 3.9.0 chacha20poly1305.vec: vector from Go crypto / WireGuard.
    auto x = encrypt(Algorithm::xchacha20_poly1305, key, Bytes(24, 0), {}, Bytes(15, 0), 3);
    check(x.ciphertext == Botan::hex_decode("789e9689e5208d7fd9e1f3c5b5341f"), "XChaCha vector ciphertext");
    check(x.tag == Botan::hex_decode("b2f7033812ac9ebd3745e2c99c7bbfeb"), "XChaCha vector tag");
    check(decrypt(Algorithm::xchacha20_poly1305, key, Bytes(24, 0), {}, x, 1) == Bytes(15, 0), "XChaCha vector decrypt");
}

void budget_tests(Algorithm algorithm) {
    const auto limit = message_limit(algorithm);
    MessageBudget budget(algorithm);
    budget.consume(limit - 1);
    budget.consume(1);
    budget.consume(0);
    try { budget.consume(1); throw std::runtime_error("Missing size error"); }
    catch(const std::length_error& e) {
        check(std::string(e.what()) == "File too large for selected AEAD", "Size error text");
    }
    check(budget.used() == limit, "Failed size check changed counter");
    MessageBudget overflow(algorithm);
    rejects<std::length_error>([&] { overflow.consume(std::numeric_limits<std::uint64_t>::max()); });
    check(overflow.used() == 0, "Overflow changed counter");
}

void roundtrip_tests(Algorithm algorithm, const SecureBytes& key, const SecureBytes& wrong_key) {
    const auto nonce = random_bytes(algorithm == Algorithm::aes256_gcm ? 12 : 24);
    const Bytes aad{1, 2, 3, 4};
    for(const std::size_t size : {0u, 1u, 15u, 16u, 17u, 63u, 64u, 65u, 4097u}) {
        Bytes plaintext(size);
        for(std::size_t i = 0; i < size; ++i) { plaintext[i] = static_cast<std::uint8_t>(i); }
        const auto reference = encrypt(algorithm, key, nonce, aad, plaintext, 8192);
        for(const std::size_t chunk : {1u, 7u, 16u, 63u, 256u}) {
            const auto encoded = encrypt(algorithm, key, nonce, aad, plaintext, chunk);
            check(encoded.ciphertext == reference.ciphertext && encoded.tag == reference.tag,
                  "Chunk boundaries changed ciphertext or tag");
            check(decrypt(algorithm, key, nonce, aad, encoded, chunk) == plaintext, "Roundtrip failed");
        }
        rejects<Botan::Invalid_Authentication_Tag>([&] { decrypt(algorithm, wrong_key, nonce, aad, reference, 7); });
        auto bad_aad = aad; bad_aad[0] ^= 1;
        rejects<Botan::Invalid_Authentication_Tag>([&] { decrypt(algorithm, key, nonce, bad_aad, reference, 7); });
        auto bad_nonce = nonce; bad_nonce[0] ^= 1;
        rejects<Botan::Invalid_Authentication_Tag>([&] { decrypt(algorithm, key, bad_nonce, aad, reference, 7); });
        auto bad_tag = reference; bad_tag.tag[0] ^= 1;
        rejects<Botan::Invalid_Authentication_Tag>([&] { decrypt(algorithm, key, nonce, aad, bad_tag, 7); });
        if(size != 0) {
            auto bad_ciphertext = reference; bad_ciphertext.ciphertext[0] ^= 1;
            rejects<Botan::Invalid_Authentication_Tag>([&] { decrypt(algorithm, key, nonce, aad, bad_ciphertext, 7); });
            auto truncated = reference; truncated.ciphertext.pop_back();
            rejects<Botan::Invalid_Authentication_Tag>([&] { decrypt(algorithm, key, nonce, aad, truncated, 7); });
        }
    }
    rejects<std::invalid_argument>([&] { Cipher cipher(algorithm, true, Bytes(31), nonce, aad); });
    rejects<std::invalid_argument>([&] { Cipher cipher(algorithm, true, key, Bytes(8), aad); });
    Cipher cipher(algorithm, false, key, nonce, aad);
    rejects<std::invalid_argument>([&] { cipher.finish(Bytes(15)); });
}

int main() {
    try {
        const Bytes password{'p', 'a', 's', 's', 0, 0xE4, 0xB8, 0xAD};
        auto salt = random_bytes(16);
        const auto key = derive_key(password, salt);
        check(key == derive_key(password, salt), "Argon2id not reproducible");
        auto wrong_password = password; wrong_password[0] ^= 1;
        const auto wrong_key = derive_key(wrong_password, salt);
        check(key != wrong_key, "Password did not affect key");
        salt[0] ^= 1;
        check(key != derive_key(password, salt), "Salt did not affect key");
        vectors();
        for(const auto algorithm : {Algorithm::aes256_gcm, Algorithm::xchacha20_poly1305}) {
            budget_tests(algorithm);
            roundtrip_tests(algorithm, key, wrong_key);
        }
        std::cout << Botan::version_string() << '\n'
                  << "PASS: vectors, Argon2id, chunk boundaries, tampering, size limits\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
