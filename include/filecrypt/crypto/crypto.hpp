#pragma once

#include <botan/secmem.h>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

namespace filecrypt::crypto {
using Bytes = std::vector<std::uint8_t>;
using SecureBytes = Botan::secure_vector<std::uint8_t>;
using Tag = std::array<std::uint8_t, 16>;

// 此枚举属于密码操作接口，不对应任何文件协议编号。
enum class Algorithm { aes256_gcm, xchacha20_poly1305 };
enum class Direction { encrypt, decrypt };

struct Argon2idParameters {
    std::uint32_t memory_kib;
    std::uint32_t iterations;
    std::uint32_t parallelism;
};

// 每次调用显式传入资源策略，不把临时策略冻结为协议常数。
struct KdfLimits {
    std::uint32_t max_memory_kib;
    std::uint32_t max_iterations;
    std::uint32_t max_parallelism;
};

class AuthenticationError : public std::runtime_error {
public:
    /// 创建稳定的认证失败异常，不暴露底层库的异常类型。
    AuthenticationError() : std::runtime_error("Authentication failed") {}
};

/// 返回算法的消息字节上限，拒绝无效算法值。
[[nodiscard]] std::uint64_t message_limit(Algorithm algorithm);
/// 返回所选算法要求的 Nonce 字节数。
[[nodiscard]] std::size_t nonce_size(Algorithm algorithm);
/// 按显式参数和资源策略派生 Argon2id 1.3 密钥，密码保持原始字节语义。
// 当前两种 AEAD 只需要 32 字节密钥；盐至少 8 字节，具体协议盐长度由应用校验。
[[nodiscard]] SecureBytes derive_key(std::span<const std::uint8_t> password,
    std::span<const std::uint8_t> salt, const Argon2idParameters& parameters,
    const KdfLimits& limits, std::size_t key_size);
/// 使用密码学安全随机数生成公开 Salt 或 Nonce 字节。
[[nodiscard]] Bytes random_bytes(std::size_t size);

class MessageBudget {
public:
    /// 为算法建立实际 AEAD 输入字节计数器。
    explicit MessageBudget(Algorithm algorithm);
    /// 检查并累计输入长度，超限时不改变计数器。
    void consume(std::uint64_t size);
    /// 返回已经接受的消息字节数。
    [[nodiscard]] std::uint64_t used() const { return used_; }
private:
    std::uint64_t limit_;
    std::uint64_t used_{};
};

struct FinalResult {
    SecureBytes output;
    // 仅加密时返回 Tag，解密成功时为空。
    Bytes tag;
};

class CipherContext {
public:
    /// 校验参数并建立带 AAD 的单消息 AEAD 上下文。
    CipherContext(Algorithm algorithm, Direction direction,
        std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> aad);
    /// 销毁上下文并释放安全缓冲区。
    ~CipherContext();
    /// 禁止复制包含密钥和消息状态的上下文。
    CipherContext(const CipherContext&) = delete;
    /// 禁止以复制赋值共享密码上下文状态。
    CipherContext& operator=(const CipherContext&) = delete;
    /// 增量处理输入，解密输出在 finish 成功前仍未认证。
    [[nodiscard]] SecureBytes update(std::span<const std::uint8_t> input);
    /// 完成加密并拆出 Tag，或使用独立 Tag 完成解密认证。
    [[nodiscard]] FinalResult finish(std::span<const std::uint8_t> tag = {});
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct Encrypted {
    Bytes ciphertext;
    Tag tag;
};

/// 在内存中加密一条消息并返回密文与独立 Tag。
[[nodiscard]] Encrypted encrypt(Algorithm algorithm, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> plaintext);
/// 在安全缓冲区暂存明文，认证成功后才返回完整结果。
[[nodiscard]] SecureBytes decrypt(Algorithm algorithm, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> ciphertext, std::span<const std::uint8_t> tag);
} // namespace filecrypt::crypto
