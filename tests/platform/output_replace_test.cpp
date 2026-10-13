#include "output_replace_test.hpp"
#include <filecrypt/io/output.hpp>
#include <filecrypt/io/source.hpp>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>

namespace test_output_replace {
namespace {
using namespace filecrypt;

/// 将事务观察结果与独立文件内容比较，不依赖被测实现的内部状态。
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

/// 写入短小夹具并关闭流，供后续快照稳定读取。
void write_file(const std::filesystem::path& path, std::string_view value) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    check(static_cast<bool>(output), "Cannot write replacement fixture");
}

/// 从磁盘重新读取夹具，确认提交或拒绝后的可见内容。
std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    check(static_cast<bool>(input), "Cannot read replacement fixture");
    return {std::istreambuf_iterator<char>(input), {}};
}

/// 失败路径必须抛出异常，不能静默报告换密成功。
template<class Action>
void rejects(Action action) {
    try { action(); }
    catch (const std::exception&) { return; }
    throw std::runtime_error("Expected replacement rejection");
}

/// 写入预期新密文样本，事务提交前不得覆盖原文件。
void write_output(io::OutputTransaction& output) {
    constexpr std::string_view value = "new-ciphertext";
    output.write(std::as_bytes(std::span(value.data(), value.size())));
}

/// 遍历独立夹具目录，检查失败和成功事务均清理本轮临时名称。
void check_no_temporary(const std::filesystem::path& directory) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
        check(!entry.path().filename().u8string().starts_with(u8".filecrypt-"), "Replacement temporary leaked");
    }
}
}

/// 在独立子目录覆盖显式替换、原文件变化、占用与父目录替换边界。
void run(const std::filesystem::path& directory) {
    const auto root = directory / "output-replacement";
    std::filesystem::create_directory(root);
    const auto target = root / std::filesystem::path(u8"换密.fcry");
    write_file(target, "old-ciphertext");
    const auto original = io::inspect_source(target);
    {
        io::OutputTransaction output(target, original);
        write_output(output);
        check(read_file(target) == "old-ciphertext", "Uncommitted replacement changed original");
    }
    check(read_file(target) == "old-ciphertext", "Abandoned replacement changed original");
    check_no_temporary(root);
    {
        io::OutputTransaction output(target, original);
        write_output(output);
        output.commit();
        rejects([&] { output.commit(); });
    }
    check(read_file(target) == "new-ciphertext", "Replacement did not publish new bytes");
    check_no_temporary(root);
    rejects([&] { io::OutputTransaction output(target, original); });
    {
        io::OutputTransaction output(target, io::inspect_source(target));
        write_output(output);
        write_file(target, "concurrent-change");
        rejects([&] { output.commit(); });
    }
    check(read_file(target) == "concurrent-change", "Replacement overwrote changed original");
    check_no_temporary(root);
    {
        io::OutputTransaction output(target, io::inspect_source(target));
        write_output(output);
        std::filesystem::rename(target, root / "moved-original");
        write_file(target, "new-path-occupant");
        rejects([&] { output.commit(); });
    }
    check(read_file(target) == "new-path-occupant", "Replacement overwrote different source identity");
    check(read_file(root / "moved-original") == "concurrent-change", "Moved original was modified");
    {
        io::OutputTransaction output(target, io::inspect_source(target));
        write_output(output);
        std::filesystem::remove(target);
        rejects([&] { output.commit(); });
    }
    check(!std::filesystem::exists(target), "Replacement recreated missing original");
    check_no_temporary(root);
    write_file(target, "locked-original");
#ifdef _WIN32
    {
        const auto expected = io::inspect_source(target);
        io::OutputTransaction output(target, expected);
        write_output(output);
        {
            io::SourceFile held(target, expected);
            rejects([&] { output.commit(); });
            held.verify_unchanged();
            check(read_file(target) == "locked-original", "Locked replacement changed original");
        }
        output.commit();
    }
    check(read_file(target) == "new-ciphertext", "Replacement failed after source handle closed");
#else
    // POSIX 父目录可被改名，事务须拒绝新的路径对象并从锚定旧目录清理临时文件。
    const auto parent = root / "parent";
    const auto moved = root / "moved-parent";
    std::filesystem::create_directory(parent);
    write_file(parent / "source", "original-parent");
    {
        io::OutputTransaction output(parent / "source", io::inspect_source(parent / "source"));
        write_output(output);
        std::filesystem::rename(parent, moved);
        std::filesystem::create_directory(parent);
        write_file(parent / "source", "competing-parent");
        rejects([&] { output.commit(); });
    }
    check(read_file(parent / "source") == "competing-parent", "Replacement followed changed parent");
    check(read_file(moved / "source") == "original-parent", "Replacement modified relocated original");
#endif
    check_no_temporary(root);
}
}
