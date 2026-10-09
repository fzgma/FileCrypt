# 格式库只处理协议数据，不依赖 IO 或密码库。
add_library(filecrypt_format
    format/detect.cpp
    format/v1/header.cpp
    format/v1/registry.cpp
    format/v1/aad.cpp
    format/v1/metadata.cpp)
add_library(FileCrypt::Format ALIAS filecrypt_format)
target_include_directories(filecrypt_format PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_features(filecrypt_format PUBLIC cxx_std_23)

# 文件操作的平台差异隔离在 IO 库中。
add_library(filecrypt_io io/file.cpp platform/file.cpp platform/output.cpp)
add_library(FileCrypt::IO ALIAS filecrypt_io)
target_include_directories(filecrypt_io PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_features(filecrypt_io PUBLIC cxx_std_23)
if(WIN32)
    target_link_libraries(filecrypt_io PRIVATE advapi32)
endif()

# 密码能力独立于协议和应用层，当前后端使用 Botan 3。
find_package(Botan 3 REQUIRED)
add_library(filecrypt_crypto crypto/botan/crypto.cpp)
add_library(FileCrypt::Crypto ALIAS filecrypt_crypto)
target_include_directories(filecrypt_crypto PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(filecrypt_crypto PUBLIC Botan::Botan)
target_compile_features(filecrypt_crypto PUBLIC cxx_std_23)

# 应用层拥有版本分发与流程编排，CLI 不直接依赖版本格式类型。
add_library(filecrypt_app app/operations.cpp app/v1/operations.cpp app/v1/crypt.cpp)
add_library(FileCrypt::App ALIAS filecrypt_app)
target_include_directories(filecrypt_app PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(filecrypt_app PRIVATE FileCrypt::Format FileCrypt::IO PUBLIC FileCrypt::Crypto)
target_compile_features(filecrypt_app PUBLIC cxx_std_23)
target_compile_options(filecrypt_app PRIVATE "$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

add_subdirectory(cli)
