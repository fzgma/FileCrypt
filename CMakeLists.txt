cmake_minimum_required(VERSION 3.24)
project(FileCrypt VERSION 0.1.0 LANGUAGES CXX)

# 项目统一使用标准 C++23，禁止静默降级和编译器扩展。
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(src)

# CLI 位于构建目录根部，格式与文件操作由独立库提供。
add_executable(filecrypt src/cli/main.cpp)
target_link_libraries(filecrypt PRIVATE FileCrypt::App)
target_compile_options(filecrypt PRIVATE "$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
