# 正式程序独立于单元测试，保持可执行文件位于 build 根目录。
add_executable(filecrypt main.cpp ../platform/password.cpp)
target_link_libraries(filecrypt PRIVATE FileCrypt::App)
if(MINGW)
    target_link_options(filecrypt PRIVATE -municode)
    # MinGW's libstdc++ keeps terminal Unicode support in the experimental archive.
    target_link_libraries(filecrypt PRIVATE stdc++exp)
endif()
set_target_properties(filecrypt PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
