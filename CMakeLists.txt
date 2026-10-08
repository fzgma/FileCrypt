cmake_minimum_required(VERSION 3.24)
project(FileCrypt VERSION 0.1.0 LANGUAGES CXX)

# 项目统一使用标准 C++23，禁止静默降级和编译器扩展。
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
add_subdirectory(src)

# 默认构建包含正式程序及启用的测试；也提供明确的全量构建入口。
if(BUILD_TESTING)
    add_subdirectory(tests)
    add_custom_target(build_all DEPENDS filecrypt unit_tests)
else()
    add_custom_target(build_all DEPENDS filecrypt)
endif()
