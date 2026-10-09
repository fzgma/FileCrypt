file(MAKE_DIRECTORY "${TEST_DIR}")
# 测试专用非敏感密码只写入已忽略的构建目录，不通过命令行传递。
file(WRITE "${TEST_DIR}/encrypt-password.txt" "test password \ntest password \n")
file(WRITE "${TEST_DIR}/decrypt-password.txt" "test password \n")
file(WRITE "${TEST_DIR}/wrong-password.txt" "wrong password\n")
file(WRITE "${TEST_DIR}/mismatch-password.txt" "test password \ndifferent\n")
file(WRITE "${TEST_DIR}/missing-confirmation.txt" "test password \n")
file(WRITE "${TEST_DIR}/empty-password.txt" "\n\n")
file(WRITE "${TEST_DIR}/input file.bin" "UTF-8 content: 中文\nline two\n")

# 使用固定非敏感管道输入执行 CLI 并验证成功状态。
function(run_success password_file)
    execute_process(COMMAND "${FILECRYPT}" ${ARGN}
        INPUT_FILE "${TEST_DIR}/${password_file}"
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error ENCODING UTF-8)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "文件命令失败：${ARGN}\n${error}")
    endif()
    set(last_output "${output}" PARENT_SCOPE)
endfunction()

# 要求失败且不发布任何输出文件。
function(run_failure password_file destination)
    file(REMOVE "${destination}")
    execute_process(COMMAND "${FILECRYPT}" ${ARGN}
        INPUT_FILE "${TEST_DIR}/${password_file}"
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error ENCODING UTF-8)
    if(result EQUAL 0 OR EXISTS "${destination}")
        message(FATAL_ERROR "失败命令发布了输出：${ARGN}")
    endif()
endfunction()

set(source "${TEST_DIR}/input file.bin")
set(restored "${TEST_DIR}/restored file.bin")
foreach(algorithm IN ITEMS aes-256-gcm xchacha20-poly1305)
    set(encrypted "${TEST_DIR}/${algorithm}.fcry")
    file(REMOVE "${encrypted}" "${restored}")
    run_success(encrypt-password.txt encrypt "${source}" "${encrypted}" --algorithm "${algorithm}"
        --memory-kib 8192 --iterations 1 --parallelism 1)
    if(NOT last_output MATCHES "加密完成" OR NOT last_output MATCHES "忘记密码")
        message(FATAL_ERROR "加密完成提示不完整")
    endif()
    run_success(decrypt-password.txt decrypt "${encrypted}" "${restored}")
    if(NOT last_output MATCHES "认证通过")
        message(FATAL_ERROR "解密未报告认证通过")
    endif()
    file(SHA256 "${source}" source_hash)
    file(SHA256 "${restored}" restored_hash)
    if(NOT source_hash STREQUAL restored_hash)
        message(FATAL_ERROR "CLI 文件往返不一致")
    endif()
    run_failure(wrong-password.txt "${TEST_DIR}/wrong.bin" decrypt "${encrypted}" "${TEST_DIR}/wrong.bin")
    run_failure(decrypt-password.txt "${TEST_DIR}/limited.bin" decrypt "${encrypted}"
        "${TEST_DIR}/limited.bin" --max-memory-kib 4096)
    # 已有输出失败时必须保持内容不变。
    execute_process(COMMAND "${FILECRYPT}" decrypt "${encrypted}" "${restored}"
        INPUT_FILE "${TEST_DIR}/decrypt-password.txt" RESULT_VARIABLE result)
    file(SHA256 "${restored}" after_hash)
    if(result EQUAL 0 OR NOT restored_hash STREQUAL after_hash)
        message(FATAL_ERROR "已有明文被覆盖")
    endif()
endforeach()

run_failure(mismatch-password.txt "${TEST_DIR}/mismatch.fcry" encrypt "${source}" "${TEST_DIR}/mismatch.fcry")
run_failure(missing-confirmation.txt "${TEST_DIR}/missing.fcry" encrypt "${source}" "${TEST_DIR}/missing.fcry")
run_failure(empty-password.txt "${TEST_DIR}/empty.fcry" encrypt "${source}" "${TEST_DIR}/empty.fcry")
run_failure(encrypt-password.txt "${TEST_DIR}/invalid.fcry" encrypt "${source}" "${TEST_DIR}/invalid.fcry"
    --memory-kib 0)
run_failure(encrypt-password.txt "${TEST_DIR}/unsupported.fcry" encrypt "${source}"
    "${TEST_DIR}/unsupported.fcry" --compressed)

# 默认 KDF 配置也必须可创建并由读取端重建。
set(default_file "${TEST_DIR}/default.fcry")
file(REMOVE "${default_file}" "${restored}")
run_success(encrypt-password.txt encrypt "${source}" "${default_file}")
run_success(decrypt-password.txt decrypt "${default_file}" "${restored}")
file(SHA256 "${restored}" restored_hash)
if(NOT restored_hash STREQUAL source_hash)
    message(FATAL_ERROR "默认参数文件往返失败")
endif()
file(GLOB temporary_files "${TEST_DIR}/.filecrypt-*.tmp")
if(temporary_files)
    message(FATAL_ERROR "CLI 遗留临时输出：${temporary_files}")
endif()
