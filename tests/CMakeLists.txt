add_executable(header_test format/v1/header_test.cpp)
target_link_libraries(header_test PRIVATE FileCrypt::Format)

add_executable(metadata_test format/v1/metadata_test.cpp)
target_link_libraries(metadata_test PRIVATE FileCrypt::Format)

add_executable(aad_test format/v1/aad_test.cpp)
target_link_libraries(aad_test PRIVATE FileCrypt::Format)

add_executable(detect_test format/detect_test.cpp)
target_link_libraries(detect_test PRIVATE FileCrypt::Format FileCrypt::App)

add_executable(crypto_test crypto/crypto_test.cpp)
target_link_libraries(crypto_test PRIVATE FileCrypt::Crypto FileCrypt::Format)

add_executable(compression_test compression/compression_test.cpp)
target_link_libraries(compression_test PRIVATE FileCrypt::Compression Zstd::Zstd)

add_executable(directory_test format/v1/directory_test.cpp)
target_link_libraries(directory_test PRIVATE FileCrypt::Format)

add_executable(expected_test format/expected_test.cpp)
target_link_libraries(expected_test PRIVATE FileCrypt::Format)

# 单元测试可单独构建，测试程序统一放在 build/tests/unit。
set(unit_test_targets header_test metadata_test aad_test detect_test crypto_test compression_test directory_test expected_test)
foreach(test_target IN LISTS unit_test_targets)
    set_target_properties(${test_target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/unit")
endforeach()
add_custom_target(unit_tests DEPENDS ${unit_test_targets})

add_executable(file_crypt_test app/file_crypt_test.cpp app/inspect_test.cpp)
target_link_libraries(file_crypt_test PRIVATE FileCrypt::App FileCrypt::IO FileCrypt::Format)
set_target_properties(file_crypt_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/integration")
add_custom_target(integration_tests DEPENDS file_crypt_test filecrypt)

add_executable(directory_crypt_test app/directory_crypt_test.cpp)
target_link_libraries(directory_crypt_test PRIVATE FileCrypt::App FileCrypt::Format FileCrypt::IO)
if(MINGW)
    target_link_options(directory_crypt_test PRIVATE -municode)
endif()
set_target_properties(directory_crypt_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/integration")
add_dependencies(integration_tests directory_crypt_test)

if(WIN32)
    add_executable(console_test cli/console_test.cpp)
    if(MINGW)
        target_link_options(console_test PRIVATE -municode)
    endif()
    set_target_properties(console_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/integration")
    add_dependencies(integration_tests console_test)
endif()

# Shared CTest registration for build and runtime verification.
set(header_test_command "$<TARGET_FILE:header_test>")
set(metadata_test_command "$<TARGET_FILE:metadata_test>")
set(aad_test_command "$<TARGET_FILE:aad_test>")
set(detect_test_command "$<TARGET_FILE:detect_test>")
set(crypto_test_command "$<TARGET_FILE:crypto_test>")
set(compression_test_command "$<TARGET_FILE:compression_test>")
set(directory_test_command "$<TARGET_FILE:directory_test>")
set(expected_test_command "$<TARGET_FILE:expected_test>")
set(file_crypt_test_command "$<TARGET_FILE:file_crypt_test>")
set(directory_crypt_test_command "$<TARGET_FILE:directory_crypt_test>")
set(filecrypt_command "$<TARGET_FILE:filecrypt>")
if(WIN32)
    set(console_test_command "$<TARGET_FILE:console_test>")
endif()
set(FILECRYPT_TEST_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
include("${FILECRYPT_TEST_SOURCE_DIR}/register_tests.cmake")
