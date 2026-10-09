cmake_minimum_required(VERSION 3.24)
project(FileCrypt VERSION 0.1.0 LANGUAGES CXX)

# 项目统一使用标准 C++23，禁止静默降级和编译器扩展。
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 输出事务与敏感内存依赖 C++ 异常展开；不可用编码选项覆盖 MSVC 默认标志。
# 统一作用于全部库、CLI 与测试，并将缺少展开语义的警告视为错误。
add_compile_options(
    "$<$<CXX_COMPILER_ID:MSVC>:/EHsc>"
    "$<$<CXX_COMPILER_ID:MSVC>:/utf-8>"
    "$<$<CXX_COMPILER_ID:MSVC>:/we4530>")

include(CTest)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
add_subdirectory(src)

# 默认构建包含正式程序及启用的测试；也提供明确的全量构建入口。
if(BUILD_TESTING)
    add_subdirectory(tests)
    add_custom_target(build_all DEPENDS filecrypt unit_tests integration_tests)
else()
    add_custom_target(build_all DEPENDS filecrypt)
endif()
