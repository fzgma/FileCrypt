# 正式程序独立于单元测试，保持可执行文件位于 build 根目录。
add_executable(filecrypt main.cpp ../platform/password.cpp)
target_link_libraries(filecrypt PRIVATE FileCrypt::App)
target_compile_options(filecrypt PRIVATE "$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
set_target_properties(filecrypt PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
