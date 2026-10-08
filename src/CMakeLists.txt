# 格式库只处理协议数据，不依赖 IO 或密码库。
add_library(filecrypt_format
    format/header.cpp
    format/registry.cpp
    format/metadata.cpp)
add_library(FileCrypt::Format ALIAS filecrypt_format)
target_include_directories(filecrypt_format PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_features(filecrypt_format PUBLIC cxx_std_23)

# 文件操作的平台差异隔离在 IO 库中。
add_library(filecrypt_io platform/file.cpp)
add_library(FileCrypt::IO ALIAS filecrypt_io)
target_include_directories(filecrypt_io PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_features(filecrypt_io PUBLIC cxx_std_23)
