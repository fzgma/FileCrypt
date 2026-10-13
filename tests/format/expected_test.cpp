#include <filecrypt/format/v1/aad.hpp>
#include <filecrypt/format/v1/registry.hpp>

#include <cstdlib>
#include <iostream>
#include <new>
#include <stdexcept>

using namespace filecrypt::format::v1;
using filecrypt::Error;
using filecrypt::ErrorCode;

namespace {
bool fail_allocation = false;
}

/// 为本测试注入下一次标准分配失败，验证结果接口不会吞掉 bad_alloc。
void* operator new(std::size_t size) {
    if (fail_allocation) {
        fail_allocation = false;
        throw std::bad_alloc();
    }
    if (void* memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
/// 释放本测试替换分配器产生的内存。
void operator delete(void* memory) noexcept { std::free(memory); }
/// 保持带大小的释放与替换分配器匹配。
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }

namespace {
/// 检查语义测试条件并报告原因。
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

/// 核对错误值的语义类别与非空诊断，不解析消息决定分类。
template<class T>
void error_is(const std::expected<T, Error>& result, ErrorCode code) {
    check(!result && result.error().code == code && !result.error().message.empty(),
        "Incorrect semantic error or missing diagnostic");
}

/// 对照原异常接口，确认标准基类和具体诊断仍被保留。
template<class Action, class T>
void matches_exception(Action action, const std::expected<T, Error>& result) {
    try { action(); }
    catch (const std::invalid_argument& error) {
        check(!result && result.error().message == error.what(), "Exception diagnostic changed");
        return;
    }
    throw std::runtime_error("Legacy format API did not throw invalid_argument");
}

/// 开启分配故障后调用接口，离开作用域时恢复正常分配。
struct AllocationFailure {
    /// 只影响下一次分配，构造守卫本身不分配内存。
    AllocationFailure() { fail_allocation = true; }
    /// 防止被测路径未分配时影响后续断言或测试。
    ~AllocationFailure() { fail_allocation = false; }
};

/// 验证实际解析或 AAD 构造时的分配失败继续作为异常传播。
template<class Action>
void propagates_allocation_failure(Action action) {
    bool propagated = false;
    {
        AllocationFailure failure;
        try { action(); } catch (const std::bad_alloc&) { propagated = true; }
    }
    check(propagated, "Allocation failure was converted to a normal error");
}

/// 构造指定算法与容器组合的合法 Header。
Header sample_header(std::uint16_t algorithm, std::uint16_t flags) {
    Header header;
    header.version = 1;
    header.algorithm = algorithm;
    header.flags = flags;
    header.file_type = (flags & 0x8000) ? 0 : 0xFFFE;
    header.metadata_length = metadata_layout(header).metadata_size;
    return header;
}

/// 构造与 Header 一致的非敏感 Metadata 样本。
Metadata sample_metadata(const Header& header) {
    Metadata metadata;
    if (header.flags & 0x8000) metadata.index_length = 0;
    if (header.flags & 0x4000) metadata.compression = CompressionMetadata{};
    metadata.kdf_parameters.memory_cost_kib = 8192;
    metadata.kdf_parameters.time_cost = 1;
    metadata.kdf_parameters.parallelism = 1;
    metadata.nonce.resize(algorithm_definition(header.algorithm).nonce_size);
    return metadata;
}

/// 验证 Header 编解码边界保持不变，格式失败返回具体语义。
void header_tests() {
    const auto header = sample_header(1, 0);
    const auto bytes = serialize(header);
    const auto parsed = try_deserialize(bytes);
    check(parsed && *parsed == header, "Expected Header success mismatch");
    for (std::size_t size = 0; size < header_size; ++size) {
        const auto short_input = std::span(bytes).first(size);
        const auto result = try_deserialize(short_input);
        error_is(result, ErrorCode::invalid_format);
        matches_exception([&] { (void)deserialize(short_input); }, result);
    }
    auto invalid = bytes;
    invalid[0] = std::byte{0};
    const auto rejected = try_deserialize(invalid);
    error_is(rejected, ErrorCode::invalid_format);
    matches_exception([&] { (void)deserialize(invalid); }, rejected);
    // Header codec 不承担版本语义校验；未知版本仍可还原逻辑字段。
    auto raw = header;
    raw.version = 2;
    const auto unknown = try_deserialize(serialize(raw));
    check(unknown && unknown->version == 2, "Header codec acquired semantic validation");
}

/// 验证八种布局的 Metadata 和两种 AAD 入口成功结果一致。
void success_tests() {
    for (const std::uint16_t algorithm : {1, 2}) {
        for (const std::uint16_t flags : {0, 0x4000, 0x8000, 0xC000}) {
            const auto header = sample_header(algorithm, flags);
            const auto metadata = sample_metadata(header);
            const auto bytes = serialize_metadata(header, metadata);
            const auto parsed = try_deserialize_metadata(header, bytes);
            check(parsed && *parsed == metadata, "Expected Metadata success mismatch");
            const auto aad = build_aad(header, metadata);
            const auto object_result = try_build_aad(header, metadata);
            const auto raw_result = try_build_aad(serialize(header), bytes);
            check(object_result && raw_result && *object_result == aad && *raw_result == aad,
                "Expected AAD success mismatch");
        }
    }
}

/// 验证不支持的编号与已知格式字段异常分别返回类别，并保留异常接口。
void semantic_tests() {
    const auto header = sample_header(1, 0xC000);
    const auto metadata = sample_metadata(header);
    const auto bytes = serialize_metadata(header, metadata);
    const auto layout = metadata_layout(header);
    for (const auto offset : {*layout.compression_offset, layout.kdf_id_offset}) {
        auto changed = bytes;
        changed[offset] = std::byte{3};
        const auto result = try_deserialize_metadata(header, changed);
        error_is(result, ErrorCode::unsupported_format);
        matches_exception([&] { (void)deserialize_metadata(header, changed); }, result);
        error_is(try_build_aad(serialize(header), changed), ErrorCode::unsupported_format);
    }
    for (const auto offset : {*layout.compression_offset + 2, layout.kdf_parameters_offset,
            layout.kdf_parameters_offset + 1, layout.kdf_parameters_offset + 8, layout.padding_offset}) {
        auto changed = bytes;
        changed[offset] = offset == layout.kdf_parameters_offset + 8 ? std::byte{0} : std::byte{1};
        const auto result = try_deserialize_metadata(header, changed);
        error_is(result, ErrorCode::invalid_format);
        matches_exception([&] { (void)deserialize_metadata(header, changed); }, result);
        error_is(try_build_aad(serialize(header), changed), ErrorCode::invalid_format);
    }
    for (std::size_t size = 0; size < bytes.size(); ++size) {
        error_is(try_deserialize_metadata(header, std::span(bytes).first(size)), ErrorCode::invalid_format);
    }
    for (int field = 0; field < 5; ++field) {
        auto changed = header;
        switch (field) {
        case 0: changed.version = 2; break;
        case 1: changed.algorithm = 3; break;
        case 2: changed.flags |= 1; break;
        case 3: changed.reserved[0] = std::byte{1}; break;
        case 4: ++changed.metadata_length; break;
        }
        const auto code = field < 2 ? ErrorCode::unsupported_format : ErrorCode::invalid_format;
        const auto result = try_deserialize_metadata(changed, bytes);
        error_is(result, code);
        matches_exception([&] { (void)deserialize_metadata(changed, bytes); }, result);
        error_is(try_build_aad(changed, metadata), code);
    }
    const auto single = sample_header(1, 0);
    const auto single_metadata = sample_metadata(single);
    const auto single_bytes = serialize_metadata(single, single_metadata);
    for (const std::uint16_t type : {0, 0x25, 0xFFFF}) {
        auto changed = single;
        changed.file_type = type;
        error_is(try_deserialize_metadata(changed, single_bytes),
            type == 0x25 ? ErrorCode::unsupported_format : ErrorCode::invalid_format);
    }
    auto bad_metadata = metadata;
    bad_metadata.nonce.clear();
    const auto bad_object = try_build_aad(header, bad_metadata);
    error_is(bad_object, ErrorCode::invalid_format);
    matches_exception([&] { (void)build_aad(header, bad_metadata); }, bad_object);
    const auto header_bytes = serialize(header);
    const auto short_aad = try_build_aad(std::span(header_bytes).first(31), bytes);
    error_is(short_aad, ErrorCode::invalid_format);
}

/// 验证旧枚举和旧标准异常转换约定，并测试新增语义与分配失败。
void compatibility_tests() {
    static_assert(static_cast<int>(ErrorCode::invalid_argument) == 0);
    static_assert(static_cast<int>(ErrorCode::length) == 1);
    static_assert(static_cast<int>(ErrorCode::logic) == 2);
    static_assert(static_cast<int>(ErrorCode::runtime) == 3);
    check(filecrypt::error_from_exception(std::invalid_argument("legacy")).code == ErrorCode::invalid_argument &&
        filecrypt::error_from_exception(std::length_error("legacy")).code == ErrorCode::length &&
        filecrypt::error_from_exception(std::logic_error("legacy")).code == ErrorCode::logic &&
        filecrypt::error_from_exception(std::runtime_error("legacy")).code == ErrorCode::runtime,
        "Legacy exception mapping changed");
    const std::bad_alloc allocation;
    bool propagated = false;
    try { (void)filecrypt::error_from_exception(allocation); }
    catch (const std::bad_alloc&) { propagated = true; }
    check(propagated, "Legacy converter swallowed bad_alloc");
    const auto header = sample_header(1, 0);
    const auto metadata = sample_metadata(header);
    const auto bytes = serialize_metadata(header, metadata);
    const auto header_bytes = serialize(header);
    propagates_allocation_failure([&] { (void)try_deserialize_metadata(header, bytes); });
    propagates_allocation_failure([&] { (void)try_build_aad(header, metadata); });
    propagates_allocation_failure([&] { (void)try_build_aad(header_bytes, bytes); });
}
}

/// 验证格式结果接口的语义分类、异常兼容与分配失败传播。
int main() {
    try {
        header_tests();
        success_tests();
        semantic_tests();
        compatibility_tests();
        std::cout << "Expected format API tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
