add_executable(header_test format/v1/header_test.cpp)
target_link_libraries(header_test PRIVATE FileCrypt::Format)
add_test(NAME format_header COMMAND header_test)

add_executable(metadata_test format/v1/metadata_test.cpp)
target_link_libraries(metadata_test PRIVATE FileCrypt::Format)
add_test(NAME format_metadata COMMAND metadata_test)

add_executable(aad_test format/v1/aad_test.cpp)
target_link_libraries(aad_test PRIVATE FileCrypt::Format)
add_test(NAME format_aad COMMAND aad_test)

add_executable(detect_test format/detect_test.cpp)
target_link_libraries(detect_test PRIVATE FileCrypt::Format FileCrypt::App)
add_test(NAME format_detect COMMAND detect_test)

add_executable(crypto_test crypto/crypto_test.cpp)
target_link_libraries(crypto_test PRIVATE FileCrypt::Crypto FileCrypt::Format)
add_test(NAME crypto_core COMMAND crypto_test)

# 单元测试可单独构建，测试程序统一放在 build/tests/unit。
set(unit_test_targets header_test metadata_test aad_test detect_test crypto_test)
foreach(test_target IN LISTS unit_test_targets)
    set_target_properties(${test_target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/unit")
endforeach()
add_custom_target(unit_tests DEPENDS ${unit_test_targets})
set_tests_properties(format_header format_metadata format_aad format_detect crypto_core
    PROPERTIES LABELS "unit")

add_test(NAME cli_info COMMAND "${CMAKE_COMMAND}"
    "-DFILECRYPT=$<TARGET_FILE:filecrypt>"
    "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-test"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cli/info_test.cmake")
set_tests_properties(cli_info PROPERTIES LABELS "integration;smoke")

add_executable(file_crypt_test app/file_crypt_test.cpp)
target_link_libraries(file_crypt_test PRIVATE FileCrypt::App FileCrypt::IO)
set_target_properties(file_crypt_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/integration")
add_custom_target(integration_tests DEPENDS file_crypt_test filecrypt)
add_test(NAME app_file_crypt COMMAND file_crypt_test "${CMAKE_CURRENT_BINARY_DIR}/file-crypt-test")
set_tests_properties(app_file_crypt PROPERTIES LABELS "integration")

add_test(NAME cli_file_crypt COMMAND "${CMAKE_COMMAND}"
    "-DFILECRYPT=$<TARGET_FILE:filecrypt>"
    "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-crypt-test"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cli/crypt_test.cmake")
set_tests_properties(cli_file_crypt PROPERTIES LABELS "integration;smoke")
