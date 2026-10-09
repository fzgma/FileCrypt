#include <filecrypt/crypto/crypto.hpp>

#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/exceptn.h>
#include <botan/pwdhash.h>
#include <algorithm>
#include <limits>

namespace filecrypt::crypto {
namespace {
/// 将密码操作枚举转换为 Botan 名称，拒绝未知枚举值。
const char* botan_name(Algorithm algorithm) {
    switch (algorithm) {
    case Algorithm::aes256_gcm: return "AES-256/GCM";
    case Algorithm::xchacha20_poly1305: return "ChaCha20Poly1305";
    default: throw std::invalid_argument("Unsupported cipher algorithm");
    }
}
}

/// 返回当前两种算法的单条消息字节上限。
std::uint64_t message_limit(Algorithm algorithm) {
    switch (algorithm) {
    case Algorithm::aes256_gcm: return (std::uint64_t{1} << 36) - 32;
    case Algorithm::xchacha20_poly1305: return (std::uint64_t{1} << 38) - 64;
    default: throw std::invalid_argument("Unsupported cipher algorithm");
    }
}

/// 返回固定的 AES-GCM 或 XChaCha Nonce 长度。
std::size_t nonce_size(Algorithm algorithm) {
    switch (algorithm) {
    case Algorithm::aes256_gcm: return 12;
    case Algorithm::xchacha20_poly1305: return 24;
    default: throw std::invalid_argument("Unsupported cipher algorithm");
    }
}

/// 在任何昂贵计算前校验参数与资源策略并派生安全容器中的密钥。
SecureBytes derive_key(std::span<const std::uint8_t> password,
    std::span<const std::uint8_t> salt, const Argon2idParameters& parameters,
    const KdfLimits& limits, std::size_t key_size) {
    if (parameters.iterations == 0 || parameters.parallelism == 0 ||
        parameters.parallelism > 0xFFFFFF ||
        parameters.memory_kib < std::uint64_t{8} * parameters.parallelism ||
        salt.size() < 8 || salt.size() > std::numeric_limits<std::uint32_t>::max() ||
        password.size() > std::numeric_limits<std::uint32_t>::max() || key_size != 32) {
        throw std::invalid_argument("Invalid Argon2id parameters, input or key size");
    }
    if (parameters.memory_kib > limits.max_memory_kib ||
        parameters.iterations > limits.max_iterations ||
        parameters.parallelism > limits.max_parallelism) {
        throw std::length_error("Argon2id resource limit exceeded");
    }
    auto family = Botan::PasswordHashFamily::create_or_throw("Argon2id");
    auto hash = family->from_params(parameters.memory_kib, parameters.iterations,
        parameters.parallelism);
    SecureBytes key(key_size);
    // 空密码使用有效空字符串地址，不执行 trim、规范化或 NUL 追加。
    const auto* password_data = password.empty() ? "" :
        reinterpret_cast<const char*>(password.data());
    hash->derive_key(key.data(), key.size(), password_data, password.size(), salt.data(), salt.size());
    return key;
}

/// 从 Botan 系统播种的安全随机源生成指定长度字节。
Bytes random_bytes(std::size_t size) {
    Bytes bytes(size);
    if (!bytes.empty()) {
        Botan::AutoSeeded_RNG rng;
        rng.randomize(bytes.data(), bytes.size());
    }
    return bytes;
}

/// 建立算法上限计数器，未知算法立即拒绝。
MessageBudget::MessageBudget(Algorithm algorithm) : limit_(message_limit(algorithm)) {}

/// 用减法检查累计消息大小，避免整数溢出。
void MessageBudget::consume(std::uint64_t size) {
    if (size > limit_ - used_) {
        throw std::length_error("File too large for selected AEAD");
    }
    used_ += size;
}

struct CipherContext::Impl {
    std::unique_ptr<Botan::AEAD_Mode> mode;
    MessageBudget budget;
    SecureBytes pending;
    Direction direction;
    bool closed{false};

    /// 创建底层密码模式和单消息计数状态。
    Impl(Algorithm algorithm, Direction selected_direction)
        : mode(Botan::AEAD_Mode::create_or_throw(botan_name(algorithm),
            selected_direction == Direction::encrypt ?
                Botan::Cipher_Dir::Encryption : Botan::Cipher_Dir::Decryption)),
          budget(algorithm), direction(selected_direction) {}

    /// 关闭失败或已完成上下文并清理安全缓冲区与底层密钥。
    void close() {
        closed = true;
        pending.clear();
        mode.reset();
    }
};

/// 校验固定参数后设置密钥、AAD 和 Nonce。
CipherContext::CipherContext(Algorithm algorithm, Direction direction,
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad) {
    if ((direction != Direction::encrypt && direction != Direction::decrypt) ||
        key.size() != 32 || nonce.size() != nonce_size(algorithm)) {
        throw std::invalid_argument("Invalid cipher direction, key or nonce size");
    }
    // AES-GCM 的 AAD 位长度使用 64 位编码；XChaCha 采用同样的保守字节限制。
    if (aad.size() > std::numeric_limits<std::uint64_t>::max() / 8) {
        throw std::length_error("AAD too large");
    }
    impl_ = std::make_unique<Impl>(algorithm, direction);
    impl_->mode->set_key(key.data(), key.size());
    impl_->mode->set_associated_data(aad.data(), aad.size());
    impl_->mode->start(nonce.data(), nonce.size());
}

/// 释放底层模式和安全容器，销毁密钥状态。
CipherContext::~CipherContext() = default;

/// 分段提交输入，内部暂存量不随单次调用的输入大小增长。
SecureBytes CipherContext::update(std::span<const std::uint8_t> input) {
    if (impl_->closed) {
        throw std::logic_error("Cipher context is closed");
    }
    try {
        impl_->budget.consume(input.size());
        SecureBytes output;
        output.reserve(input.size());
        const auto granularity = impl_->mode->update_granularity();
        while (!input.empty()) {
            const auto take = std::min(input.size(), granularity - impl_->pending.size());
            impl_->pending.insert(impl_->pending.end(), input.begin(), input.begin() + take);
            input = input.subspan(take);
            if (impl_->pending.size() == granularity) {
                const auto written = impl_->mode->process(impl_->pending.data(), granularity);
                output.insert(output.end(), impl_->pending.begin(), impl_->pending.begin() + written);
                impl_->pending.clear();
            }
        }
        return output;
    } catch (...) {
        impl_->close();
        throw;
    }
}

/// 终结单消息并拆分或验证独立 Tag，任何失败都使上下文不可再用。
FinalResult CipherContext::finish(std::span<const std::uint8_t> tag) {
    if (impl_->closed) {
        throw std::logic_error("Cipher context is closed");
    }
    try {
        const bool encrypting = impl_->direction == Direction::encrypt;
        if ((encrypting && !tag.empty()) || (!encrypting && tag.size() != 16)) {
            throw std::invalid_argument("Invalid authentication tag size");
        }
        if (!encrypting) {
            impl_->pending.insert(impl_->pending.end(), tag.begin(), tag.end());
        }
        impl_->mode->finish(impl_->pending);
        FinalResult result;
        if (encrypting) {
            const auto tag_start = impl_->pending.end() - 16;
            result.tag.assign(tag_start, impl_->pending.end());
            impl_->pending.erase(tag_start, impl_->pending.end());
        }
        result.output = std::move(impl_->pending);
        impl_->close();
        return result;
    } catch (const Botan::Invalid_Authentication_Tag&) {
        impl_->close();
        throw AuthenticationError();
    } catch (...) {
        impl_->close();
        throw;
    }
}

/// 完成单消息内存加密并转换公开密文和固定 Tag。
Encrypted encrypt(Algorithm algorithm, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> plaintext) {
    CipherContext context(algorithm, Direction::encrypt, key, nonce, aad);
    auto output = context.update(plaintext);
    auto final = context.finish();
    output.insert(output.end(), final.output.begin(), final.output.end());
    Encrypted result;
    result.ciphertext.assign(output.begin(), output.end());
    std::copy(final.tag.begin(), final.tag.end(), result.tag.begin());
    return result;
}

/// 在认证成功前保持明文私有，失败时由安全容器清理暂存数据。
SecureBytes decrypt(Algorithm algorithm, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> ciphertext, std::span<const std::uint8_t> tag) {
    CipherContext context(algorithm, Direction::decrypt, key, nonce, aad);
    auto plaintext = context.update(ciphertext);
    auto final = context.finish(tag);
    plaintext.insert(plaintext.end(), final.output.begin(), final.output.end());
    return plaintext;
}
} // namespace filecrypt::crypto
