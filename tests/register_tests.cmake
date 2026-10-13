# Single source of test commands, labels and timeouts.
add_test(NAME format_header COMMAND ${FILECRYPT_TEST_RUNNER} "${header_test_command}")
add_test(NAME format_metadata COMMAND ${FILECRYPT_TEST_RUNNER} "${metadata_test_command}")
add_test(NAME format_aad COMMAND ${FILECRYPT_TEST_RUNNER} "${aad_test_command}")
add_test(NAME format_detect COMMAND ${FILECRYPT_TEST_RUNNER} "${detect_test_command}")
add_test(NAME crypto_core COMMAND ${FILECRYPT_TEST_RUNNER} "${crypto_test_command}")
add_test(NAME compression_core COMMAND ${FILECRYPT_TEST_RUNNER} "${compression_test_command}")
add_test(NAME format_directory COMMAND ${FILECRYPT_TEST_RUNNER} "${directory_test_command}")
add_test(NAME format_expected COMMAND ${FILECRYPT_TEST_RUNNER} "${expected_test_command}")
set_tests_properties(format_header format_metadata format_aad format_detect crypto_core compression_core format_directory
    format_expected PROPERTIES LABELS "unit")
add_test(NAME cli_info COMMAND "${CMAKE_COMMAND}"
    "-DFILECRYPT=${filecrypt_command}"
    "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-test"
    -P "${FILECRYPT_TEST_SOURCE_DIR}/cli/info_test.cmake")
set_tests_properties(cli_info PROPERTIES LABELS "integration;smoke")
add_test(NAME app_file_crypt COMMAND ${FILECRYPT_TEST_RUNNER} "${file_crypt_test_command}" "${CMAKE_CURRENT_BINARY_DIR}/file-crypt-test")
set_tests_properties(app_file_crypt PROPERTIES LABELS "integration")
add_test(NAME app_directory_crypt COMMAND ${FILECRYPT_TEST_RUNNER} "${directory_crypt_test_command}" "${CMAKE_CURRENT_BINARY_DIR}/directory-crypt-test")
set_tests_properties(app_directory_crypt PROPERTIES LABELS "integration")
add_test(NAME cli_file_crypt COMMAND "${CMAKE_COMMAND}"
    "-DFILECRYPT=${filecrypt_command}"
    "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-crypt-test"
    -P "${FILECRYPT_TEST_SOURCE_DIR}/cli/crypt_test.cmake")
set_tests_properties(cli_file_crypt PROPERTIES LABELS "integration;smoke")
add_test(NAME cli_directory_crypt COMMAND "${CMAKE_COMMAND}"
    "-DFILECRYPT=${filecrypt_command}" "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-directory-test"
    "-DCLEANUP_TOOL=${directory_crypt_test_command}"
    -P "${FILECRYPT_TEST_SOURCE_DIR}/cli/directory_test.cmake")
set_tests_properties(cli_directory_crypt PROPERTIES LABELS "integration;smoke")
add_test(NAME cli_directory_corpus COMMAND "${CMAKE_COMMAND}"
    "-DFILECRYPT=${filecrypt_command}" "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/corpus-test"
    -P "${FILECRYPT_TEST_SOURCE_DIR}/cli/corpus_test.cmake")
set(corpus_timeout 180)
if(FILECRYPT_TEST_CPU_BASELINE)
    set(corpus_timeout 360)
endif()
set_tests_properties(cli_directory_corpus PROPERTIES LABELS "integration;corpus" TIMEOUT ${corpus_timeout})
if(WIN32)
    add_test(NAME cli_console_unicode COMMAND "${console_test_command}" "${filecrypt_command}")
    set_tests_properties(cli_console_unicode PROPERTIES LABELS "integration;smoke" TIMEOUT 75)
endif()
