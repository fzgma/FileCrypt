#include <filecrypt/crypto/crypto.hpp>
#include <filecrypt/format/v1/aad.hpp>
#include <botan/hex.h>
#include <botan/version.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

using namespace filecrypt::crypto;
namespace {

/// 检查测试条件并在失败时报告原因。
void check(bool condition, const char* message) {
    if(!condition) { throw std::runtime_error(message); }
}
/// 验证操作会抛出指定类型的异常。
template<class Error, class Function>
void rejects(Function function) {
    try { function(); }
    catch(const Error&) { return; }
    throw std::runtime_error("Expected error was not raised");
}
/// 将增量返回的字节追加到测试结果。
template <typename Container>
void append(Bytes& output, const Container& part) {
    output.insert(output.end(), part.begin(), part.end());
}
/// 按指定分块大小执行增量加密并检查终结状态。
Encrypted encrypt(Algorithm algorithm, std::span<const std::uint8_t> key,
                  const Bytes& nonce, const Bytes& aad, const Bytes& input, std::size_t chunk) {
    CipherContext cipher(algorithm, Direction::encrypt, key, nonce, aad);
    Encrypted output;
    for(std::size_t offset = 0; offset < input.size(); offset += chunk) {
        append(output.ciphertext, cipher.update(std::span(input).subspan(
            offset, std::min(chunk, input.size() - offset))));
    }
    auto tail = cipher.finish();
    append(output.ciphertext, tail.output);
    std::copy(tail.tag.begin(), tail.tag.end(), output.tag.begin());
    rejects<std::logic_error>([&] { (void)cipher.update({}); });
    rejects<std::logic_error>([&] { (void)cipher.finish(); });
    return output;
}
/// 暂存增量明文并在认证成功后返回测试结果。
Bytes decrypt(Algorithm algorithm, std::span<const std::uint8_t> key,
              const Bytes& nonce, const Bytes& aad, const Encrypted& input, std::size_t chunk) {
    CipherContext cipher(algorithm, Direction::decrypt, key, nonce, aad);
    // 认证成功前测试暂存明文只用于固定非敏感样本。
    Bytes staging;
    for(std::size_t offset = 0; offset < input.ciphertext.size(); offset += chunk) {
        append(staging, cipher.update(std::span(input.ciphertext).subspan(
            offset, std::min(chunk, input.ciphertext.size() - offset))));
    }
    append(staging, cipher.finish(input.tag).output);
    return staging;
}

/// 验证 AES-GCM 与 XChaCha 的独立固定向量。
void vectors() {
    const Bytes key(32, 0);
    // AES-256-GCM 零密钥、零 IV 向量来自 NIST GCM 示例。
    auto aes = encrypt(Algorithm::aes256_gcm, key, Bytes(12, 0), {}, Bytes(16, 0), 1);
    check(aes.ciphertext == Botan::hex_decode("cea7403d4d606b6e074ec5d3baf39d18"), "AES vector ciphertext");
    check(std::ranges::equal(aes.tag, Botan::hex_decode("d0d1c8a799996bf0265b98b5d48ab919")), "AES vector tag");
    check(decrypt(Algorithm::aes256_gcm, key, Bytes(12, 0), {}, aes, 3) == Bytes(16, 0), "AES vector decrypt");
    // XChaCha 向量来自 Botan 3.9.0 的 chacha20poly1305.vec。
    auto x = encrypt(Algorithm::xchacha20_poly1305, key, Bytes(24, 0), {}, Bytes(15, 0), 3);
    check(x.ciphertext == Botan::hex_decode("789e9689e5208d7fd9e1f3c5b5341f"), "XChaCha vector ciphertext");
    check(std::ranges::equal(x.tag, Botan::hex_decode("b2f7033812ac9ebd3745e2c99c7bbfeb")), "XChaCha vector tag");
    check(decrypt(Algorithm::xchacha20_poly1305, key, Bytes(24, 0), {}, x, 1) == Bytes(15, 0), "XChaCha vector decrypt");
}

/// 验证消息大小上限和溢出输入不会改变计数。
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

/// 验证空输入、分块边界、篡改拒绝及参数检查。
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
        rejects<AuthenticationError>([&] { decrypt(algorithm, wrong_key, nonce, aad, reference, 7); });
        auto bad_aad = aad; bad_aad[0] ^= 1;
        rejects<AuthenticationError>([&] { decrypt(algorithm, key, nonce, bad_aad, reference, 7); });
        auto bad_nonce = nonce; bad_nonce[0] ^= 1;
        rejects<AuthenticationError>([&] { decrypt(algorithm, key, bad_nonce, aad, reference, 7); });
        auto bad_tag = reference; bad_tag.tag[0] ^= 1;
        rejects<AuthenticationError>([&] { decrypt(algorithm, key, nonce, aad, bad_tag, 7); });
        if(size != 0) {
            auto bad_ciphertext = reference; bad_ciphertext.ciphertext[0] ^= 1;
            rejects<AuthenticationError>([&] { decrypt(algorithm, key, nonce, aad, bad_ciphertext, 7); });
            auto truncated = reference; truncated.ciphertext.pop_back();
            rejects<AuthenticationError>([&] { decrypt(algorithm, key, nonce, aad, truncated, 7); });
        }
    }
    rejects<std::invalid_argument>([&] { CipherContext cipher(algorithm, Direction::encrypt, Bytes(31), nonce, aad); });
    rejects<std::invalid_argument>([&] { CipherContext cipher(algorithm, Direction::encrypt, key, Bytes(8), aad); });
    CipherContext cipher(algorithm, Direction::decrypt, key, nonce, aad);
    rejects<std::invalid_argument>([&] { (void)cipher.finish(Bytes(15)); });
}

/// 验证显式 KDF 参数、资源限制和密码原始字节语义。
void kdf_tests() {
    const KdfLimits limits{16384, 4, 4};
    const Argon2idParameters parameters{8192, 1, 1};
    const Bytes password{'p', 0, 0xE4, 0xB8, 0xAD};
    const Bytes salt(16, 0x42);
    const auto key = derive_key(password, salt, parameters, limits, 32);
    for (const auto changed : {Argon2idParameters{16384, 1, 1},
            Argon2idParameters{8192, 2, 1}, Argon2idParameters{8192, 1, 2}}) {
        check(key != derive_key(password, salt, changed, limits, 32), "KDF parameter ignored");
    }
    for (const auto invalid : {Argon2idParameters{7, 1, 1},
            Argon2idParameters{8192, 0, 1}, Argon2idParameters{8192, 1, 0},
            Argon2idParameters{8192, 1, 0xFFFFFFFF}}) {
        rejects<std::invalid_argument>([&] {
            (void)derive_key(password, salt, invalid, limits, 32);
        });
    }
    for (const auto resource_limits : {KdfLimits{8191, 4, 4}, KdfLimits{16384, 0, 4},
            KdfLimits{16384, 4, 0}}) {
        rejects<std::length_error>([&] {
            (void)derive_key(password, salt, parameters, resource_limits, 32);
        });
    }
    const Argon2idParameters huge{0xFFFFFFFF, 0xFFFFFFFF, 1};
    rejects<std::length_error>([&] { (void)derive_key(password, salt, huge, limits, 32); });
    rejects<std::invalid_argument>([&] { (void)derive_key(password, Bytes(7), parameters, limits, 32); });
    rejects<std::invalid_argument>([&] { (void)derive_key(password, salt, parameters, limits, 31); });
    const auto empty_key = derive_key({}, salt, parameters, limits, 32);
    check(empty_key.size() == 32, "Empty password derivation failed");
    auto space = password;
    space.push_back(' ');
    check(key != derive_key(space, salt, parameters, limits, 32), "Password was trimmed");
    check(key != derive_key(std::span(password).first(1), salt, parameters, limits, 32),
          "Password was truncated at NUL");
    check(random_bytes(0).empty() && random_bytes(16).size() == 16 && random_bytes(24).size() == 24,
          "Random byte output size mismatch");
}

/// 验证高层明文返回与增量上下文在终结或认证失败后的关闭行为。
void state_tests() {
    const Bytes key(32, 0);
    const Bytes input(4097, 0x42);
    for (const auto algorithm : {Algorithm::aes256_gcm, Algorithm::xchacha20_poly1305}) {
        const Bytes nonce(nonce_size(algorithm), 0);
        const auto encrypted = filecrypt::crypto::encrypt(algorithm, key, nonce, {}, input);
        check(std::ranges::equal(filecrypt::crypto::decrypt(algorithm, key, nonce, {},
            encrypted.ciphertext, encrypted.tag), input), "High-level roundtrip failed");
        auto wrong_tag = encrypted.tag;
        wrong_tag[0] ^= 1;
        rejects<AuthenticationError>([&] {
            (void)filecrypt::crypto::decrypt(algorithm, key, nonce, {}, encrypted.ciphertext, wrong_tag);
        });
        CipherContext failed(algorithm, Direction::decrypt, key, nonce, {});
        (void)failed.update(encrypted.ciphertext);
        rejects<AuthenticationError>([&] { (void)failed.finish(wrong_tag); });
        rejects<std::logic_error>([&] { (void)failed.update({}); });
        rejects<std::logic_error>([&] { (void)failed.finish(encrypted.tag); });
        CipherContext malformed(algorithm, Direction::decrypt, key, nonce, {});
        rejects<std::invalid_argument>([&] { (void)malformed.finish(Bytes(15)); });
        rejects<std::logic_error>([&] { (void)malformed.update({}); });
        CipherContext extra_tag(algorithm, Direction::encrypt, key, nonce, {});
        rejects<std::invalid_argument>([&] { (void)extra_tag.finish(encrypted.tag); });
        rejects<std::logic_error>([&] { (void)extra_tag.finish(); });
        CipherContext successful(algorithm, Direction::decrypt, key, nonce, {});
        (void)successful.update(encrypted.ciphertext);
        (void)successful.finish(encrypted.tag);
        rejects<std::logic_error>([&] { (void)successful.update({}); });
        rejects<std::logic_error>([&] { (void)successful.finish(encrypted.tag); });
    }
    const auto invalid_algorithm = static_cast<Algorithm>(-1);
    rejects<std::invalid_argument>([&] { (void)message_limit(invalid_algorithm); });
    rejects<std::invalid_argument>([&] { (void)nonce_size(invalid_algorithm); });
    rejects<std::invalid_argument>([&] {
        CipherContext invalid(invalid_algorithm, Direction::encrypt, key, Bytes(12), {});
    });
    rejects<std::invalid_argument>([&] {
        CipherContext invalid(Algorithm::aes256_gcm, static_cast<Direction>(-1), key, Bytes(12), {});
    });
}

/// 将格式字节显式转换为密码层字节，不在库中引入协议依赖。
Bytes crypto_bytes(std::span<const std::byte> bytes) {
    Bytes output;
    output.reserve(bytes.size());
    for (const auto value : bytes) {
        output.push_back(std::to_integer<std::uint8_t>(value));
    }
    return output;
}

/// 验证 v1 Metadata 参数重建密钥及原始 AAD 与独立 Tag 的内存闭环。
void v1_aad_tests() {
    namespace format = filecrypt::format::v1;
    const Bytes password{'p', 0, 'w'};
    const KdfLimits limits{16384, 4, 4};
    for (const auto algorithm : {Algorithm::aes256_gcm, Algorithm::xchacha20_poly1305}) {
        format::Header header;
        header.version = 1;
        // 编号转换属于应用或测试适配层，不进入 Crypto 库。
        header.algorithm = algorithm == Algorithm::aes256_gcm ? 1 : 2;
        header.file_type = 0xFFFE;
        header.metadata_length = format::metadata_layout(header).metadata_size;
        format::Metadata metadata;
        metadata.kdf_parameters.memory_cost_kib = 8192;
        metadata.kdf_parameters.time_cost = 1;
        metadata.kdf_parameters.parallelism = 1;
        const auto salt = random_bytes(16);
        std::transform(salt.begin(), salt.end(), metadata.salt.begin(),
            [](std::uint8_t value) { return static_cast<std::byte>(value); });
        const auto nonce = random_bytes(nonce_size(algorithm));
        for (const auto value : nonce) {
            metadata.nonce.push_back(static_cast<std::byte>(value));
        }
        const auto aad = crypto_bytes(format::build_aad(header, metadata));
        const auto key = derive_key(password, salt, {8192, 1, 1}, limits, 32);
        const Bytes plaintext{0, 1, 2, 3, 4};
        const auto encrypted = filecrypt::crypto::encrypt(algorithm, key, nonce, aad, plaintext);
        std::transform(encrypted.tag.begin(), encrypted.tag.end(), metadata.tag.begin(),
            [](std::uint8_t value) { return static_cast<std::byte>(value); });
        const auto raw_header = format::serialize(header);
        const auto raw_metadata = format::serialize_metadata(header, metadata);
        const auto parsed = format::deserialize_metadata(header, raw_metadata);
        const auto& p = parsed.kdf_parameters;
        const auto rebuilt_key = derive_key(password, crypto_bytes(parsed.salt),
            {p.memory_cost_kib, p.time_cost, p.parallelism}, limits, 32);
        const auto read_aad = crypto_bytes(format::build_aad(raw_header, raw_metadata));
        check(read_aad == aad && rebuilt_key == key, "v1 AAD or key reconstruction mismatch");
        check(std::ranges::equal(filecrypt::crypto::decrypt(algorithm, rebuilt_key,
            crypto_bytes(parsed.nonce), read_aad, encrypted.ciphertext, crypto_bytes(parsed.tag)),
            plaintext), "v1 memory decryption failed");
        auto changed = metadata;
        ++changed.kdf_parameters.time_cost;
        const auto changed_aad = crypto_bytes(format::build_aad(header, changed));
        rejects<AuthenticationError>([&] {
            (void)filecrypt::crypto::decrypt(algorithm, key, nonce, changed_aad,
                encrypted.ciphertext, encrypted.tag);
        });
    }
}

} // namespace

/// 执行全部密码层测试并报告测试结果。
int main() {
    try {
        const Bytes password{'p', 'a', 's', 's', 0, 0xE4, 0xB8, 0xAD};
        auto salt = random_bytes(16);
        const Argon2idParameters parameters{8192, 1, 1};
        const KdfLimits limits{16384, 4, 4};
        const auto key = derive_key(password, salt, parameters, limits, 32);
        check(key == derive_key(password, salt, parameters, limits, 32), "Argon2id not reproducible");
        auto wrong_password = password; wrong_password[0] ^= 1;
        const auto wrong_key = derive_key(wrong_password, salt, parameters, limits, 32);
        check(key != wrong_key, "Password did not affect key");
        salt[0] ^= 1;
        check(key != derive_key(password, salt, parameters, limits, 32), "Salt did not affect key");
        vectors();
        kdf_tests();
        state_tests();
        v1_aad_tests();
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
