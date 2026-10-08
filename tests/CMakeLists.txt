add_executable(header_test format/v1/header_test.cpp)
target_link_libraries(header_test PRIVATE FileCrypt::Format)
add_test(NAME format_header COMMAND header_test)

add_executable(metadata_test format/v1/metadata_test.cpp)
target_link_libraries(metadata_test PRIVATE FileCrypt::Format)
add_test(NAME format_metadata COMMAND metadata_test)

add_executable(detect_test format/detect_test.cpp)
target_link_libraries(detect_test PRIVATE FileCrypt::Format FileCrypt::App)
add_test(NAME format_detect COMMAND detect_test)

add_test(NAME cli_info COMMAND "${CMAKE_COMMAND}"
    "-DFILECRYPT=$<TARGET_FILE:filecrypt>"
    "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-test"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cli/info_test.cmake")
