#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace {
// 测试路径由 CMake 提供，不包含引号；保留 Unicode 与空格。
DWORD run_process(std::wstring command, DWORD flags = 0, bool hidden = false) {
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    if (hidden) {
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
    }
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, flags,
            nullptr, nullptr, &startup, &process)) {
        throw std::runtime_error("Cannot start console test process");
    }
    CloseHandle(process.hThread);
    const auto wait = WaitForSingleObject(process.hProcess, 30000);
    DWORD result{};
    if (wait != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &result)) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        throw std::runtime_error("Console test process failed or timed out");
    }
    CloseHandle(process.hProcess);
    return result;
}

void verify_console(const std::wstring& executable, const wchar_t* arguments,
        DWORD expected_exit, const wchar_t* expected_text) {
    const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (!GetConsoleScreenBufferInfo(output, &info)) {
        throw std::runtime_error("Cannot inspect console buffer");
    }
    const auto cells = static_cast<DWORD>(info.dwSize.X) * info.dwSize.Y;
    DWORD count{};
    if (!FillConsoleOutputCharacterW(output, L' ', cells, {0, 0}, &count) ||
        !SetConsoleCursorPosition(output, {0, 0}) || !SetConsoleOutputCP(936)) {
        throw std::runtime_error("Cannot prepare non-UTF-8 console");
    }
    const auto result = run_process(L"\"" + executable + L"\" " + arguments);
    if (result != expected_exit || GetConsoleOutputCP() != 936) {
        throw std::runtime_error("CLI exit code or console code-page restoration failed");
    }
    const DWORD capture_size = cells < 4096 ? cells : 4096;
    std::wstring text(capture_size, L'\0');
    if (!ReadConsoleOutputCharacterW(output, text.data(), capture_size, {0, 0}, &count)) {
        throw std::runtime_error("Cannot read Unicode console output");
    }
    text.resize(count);
    if (text.find(expected_text) == std::wstring::npos) {
        const auto end = text.find_last_not_of(L' ');
        text.resize(end == std::wstring::npos ? 0 : end + 1);
        // 只记录测试命令的公开输出，方便在无交互的 Actions 中诊断。
        const auto size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
            nullptr, 0, nullptr, nullptr);
        std::string utf8(static_cast<std::size_t>(size), '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
            utf8.data(), size, nullptr, nullptr);
        throw std::runtime_error("Console output did not preserve Unicode text: " + utf8);
    }
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 4 && std::wstring(argv[1]) == L"--worker") {
            // 独立隐藏控制台同时验证 stdout、stderr 及原代码页恢复。
            verify_console(argv[2], L"-h", 0, L"用法：");
            // 旧控制台屏幕缓冲区对 emoji 的表示不稳定；完整 emoji 字节另由管道测试验证。
            verify_console(argv[2], L"sample unused.fcry \"中文🔑\"", 1, L"未知选项：中文");
            return 0;
        }
        if (argc != 2) {
            throw std::runtime_error("Expected CLI executable path");
        }
        std::wstring self(32768, L'\0');
        const auto length = GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size()));
        if (length == 0 || length >= self.size()) {
            throw std::runtime_error("Cannot locate console test executable");
        }
        self.resize(length);
        const auto log = self + L".log";
        std::filesystem::remove(std::filesystem::path(log));
        const auto result = run_process(L"\"" + self + L"\" --worker \"" + argv[1] + L"\" \"" + log + L"\"",
            CREATE_NEW_CONSOLE, true);
        if (result != 0) {
            std::ifstream diagnostics{std::filesystem::path(log)};
            std::cerr << diagnostics.rdbuf();
            throw std::runtime_error("Hidden console Unicode checks failed");
        }
        return 0;
    } catch (const std::exception& error) {
        if (argc == 4) {
            std::ofstream diagnostics{std::filesystem::path(argv[3])};
            diagnostics << error.what() << '\n';
        }
        std::cerr << error.what() << '\n';
        return 1;
    }
}
