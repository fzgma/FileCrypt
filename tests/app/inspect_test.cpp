#include "inspect_test.hpp"
#include "../../src/app/v1/operations.hpp"
#include <filecrypt/format/v1/aad.hpp>
#include <filecrypt/io/file.hpp>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <new>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace test_inspect {
namespace {
using namespace filecrypt;
namespace format = filecrypt::format::v1;

/// 检查信息读取测试条件并报告失败原因。
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

/// 对照原 API 的全部展示字段，避免仅比较版本号掩盖信息变化。
bool same_info(const app::FileInfo& a, const app::FileInfo& b) {
    return std::tie(a.version, a.algorithm, a.compressed, a.compression, a.directory, a.file_type,
               a.kdf, a.details, a.has_payload, a.authenticated) ==
        std::tie(b.version, b.algorithm, b.compressed, b.compression, b.directory, b.file_type,
            b.kdf, b.details, b.has_payload, b.authenticated);
}

/// 读取非敏感格式样本的原始字节，用于独立截断与字段修改。
std::vector<std::byte> read_fixture(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    check(static_cast<bool>(input), "Cannot read info fixture");
    const std::string text{std::istreambuf_iterator<char>(input), {}};
    const auto bytes = std::as_bytes(std::span(text));
    return {bytes.begin(), bytes.end()};
}

/// 替换本轮夹具样本，不接触测试目录以外的文件。
void write_fixture(const std::filesystem::path& path, std::span<const std::byte> bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    check(static_cast<bool>(output), "Cannot write info fixture");
}

/// 检查应用结果接口失败类别，并验证原异常接口保留对应标准基类。
template<class Exception>
void rejects_as(const std::filesystem::path& path, ErrorCode code) {
    const auto result = app::try_inspect_file(path);
    check(!result && result.error().code == code && !result.error().message.empty(),
        "Incorrect info error category");
    try { (void)app::inspect_file(path); }
    catch (const Exception& error) {
        check(result.error().message == error.what(), "Legacy info diagnostic changed");
        return;
    }
    throw std::runtime_error("Legacy info exception base changed");
}

/// 验证全部格式样本和任意载荷的公开信息保持一致且未认证。
void success_tests(const std::filesystem::path& path) {
    for (const auto algorithm : {"aes-256-gcm", "xchacha20-poly1305"}) {
        for (const bool directory : {false, true}) {
            for (const bool compressed : {false, true}) {
                std::filesystem::remove(path);
                app::generate_sample(path, {1, algorithm, directory, compressed});
                const auto result = app::try_inspect_file(path);
                check(result && same_info(*result, app::inspect_file(path)) &&
                    !result->authenticated && !result->has_payload, "Info sample success mismatch");
                auto bytes = read_fixture(path);
                bytes.push_back(std::byte{0x42});
                write_fixture(path, bytes);
                const auto payload = app::try_inspect_file(path);
                check(payload && same_info(*payload, app::inspect_file(path)) &&
                    payload->has_payload && !payload->authenticated, "Payload was authenticated by info");
            }
        }
    }
}

/// 验证前缀、字段和布局错误由信息读取边界返回可靠分类。
void error_tests(const std::filesystem::path& path) {
    rejects_as<std::runtime_error>({}, ErrorCode::invalid_argument);
    std::filesystem::remove(path);
    app::generate_sample(path, {1, "aes-256-gcm", false, false});
    const auto bytes = read_fixture(path);
    for (const auto size : {std::size_t{0}, std::size_t{5}, std::size_t{6}, std::size_t{31}, bytes.size() - 1}) {
        write_fixture(path, std::span(bytes).first(size));
        rejects_as<std::runtime_error>(path, ErrorCode::invalid_format);
    }
    const auto header = format::deserialize(bytes);
    const auto layout = format::metadata_layout(header);
    for (int field = 0; field < 9; ++field) {
        auto changed = bytes;
        switch (field) {
        case 0: changed[0] = std::byte{0}; break;
        case 1: changed[4] = std::byte{2}; break;
        case 2: changed[8] = std::byte{3}; break;
        case 3: changed[10] = std::byte{0x25}; changed[11] = std::byte{0}; break;
        case 4: changed[10] = std::byte{0xFF}; break;
        case 5: changed[6] = std::byte{1}; break;
        case 6: changed[12] = std::byte{0}; break;
        case 7: changed[32 + layout.padding_offset] = std::byte{1}; break;
        case 8: changed[32 + layout.kdf_id_offset] = std::byte{3}; break;
        }
        write_fixture(path, changed);
        rejects_as<std::invalid_argument>(path,
            (field >= 1 && field <= 3) || field == 8 ? ErrorCode::unsupported_format : ErrorCode::invalid_format);
    }
    const auto missing = path.parent_path() / "missing-info.fcry";
    rejects_as<std::runtime_error>(missing, ErrorCode::io_error);
}

enum class Fault { io, allocation };

/// 在指定字节之后注入读取故障，独立验证 Header、Metadata 和载荷前瞻路径。
class FaultBuffer : public std::streambuf {
public:
    /// 保存可读前缀与故障类型，不依赖文件权限或系统错误文本。
    FaultBuffer(std::span<const std::byte> bytes, Fault fault) : bytes_(bytes), fault_(fault) {}
protected:
    /// 提供完整请求或在前缀耗尽时抛出故障。
    std::streamsize xsgetn(char* output, std::streamsize size) override {
        const auto count = std::min(static_cast<std::size_t>(size), bytes_.size() - position_);
        for (std::size_t i = 0; i < count; ++i) output[i] = std::to_integer<char>(bytes_[position_++]);
        if (count < static_cast<std::size_t>(size)) fail();
        return static_cast<std::streamsize>(count);
    }
    /// 为 peek 提供下一个字节；耗尽时注入故障而非正常 EOF。
    int_type underflow() override {
        if (position_ == bytes_.size()) fail();
        return traits_type::to_int_type(std::to_integer<char>(bytes_[position_]));
    }
private:
    /// 模拟真实读取异常或内存分配失败。
    [[noreturn]] void fail() const {
        if (fault_ == Fault::allocation) throw std::bad_alloc();
        throw std::runtime_error("Injected input fault");
    }
    std::span<const std::byte> bytes_;
    std::size_t position_{};
    Fault fault_;
};

/// 验证 IO 与 v1 信息读取区分 EOF、读取故障和分配失败，并恢复异常掩码。
void stream_tests(const std::filesystem::path& path) {
    std::filesystem::remove(path);
    app::generate_sample(path, {1, "aes-256-gcm", false, false});
    const auto bytes = read_fixture(path);
    for (const auto mask : {std::ios::goodbit, std::ios::badbit | std::ios::failbit | std::ios::eofbit}) {
        std::istringstream short_input("x");
        short_input.exceptions(mask);
        std::array<std::byte, 2> target{};
        bool ended = false;
        try { io::read_exact(short_input, target); }
        catch (const io::UnexpectedEndOfInput&) { ended = true; }
        check(ended && short_input.exceptions() == mask, "Short read or mask restoration failed");
        std::istringstream empty;
        empty.exceptions(mask);
        check(!io::has_data(empty) && empty.exceptions() == mask, "Normal EOF or peek mask restoration failed");
        for (const auto size : {std::size_t{0}, format::header_size, bytes.size()}) {
            for (const auto fault : {Fault::io, Fault::allocation}) {
                FaultBuffer buffer{std::span(bytes).first(size), fault};
                std::istream input(&buffer);
                input.exceptions(mask);
                bool rejected = false;
                try { (void)app::v1::inspect(input); }
                catch (const std::bad_alloc&) { rejected = fault == Fault::allocation; }
                catch (const OperationError& error) {
                    rejected = fault == Fault::io && error.code() == ErrorCode::io_error;
                }
                check(rejected && input.exceptions() == mask, "Stream fault category or mask restoration failed");
            }
        }
        // 预置 badbit 与 EOF 同时存在时，必须优先返回真实 IO 故障。
        std::istringstream broken;
        broken.setstate(std::ios::badbit | std::ios::eofbit);
        bool io_failure = false;
        try { io::read_exact(broken, target); }
        catch (const OperationError& error) { io_failure = error.code() == ErrorCode::io_error; }
        check(io_failure, "Bad stream was treated as normal EOF");
    }
}
}

/// 在本轮独立夹具内执行信息读取的成功、分类与输入故障回归。
void run(const std::filesystem::path& directory) {
    const auto path = directory / std::filesystem::path(u8"信息 样本 🔑.fcry");
    success_tests(path);
    error_tests(path);
    stream_tests(path);
}
}
