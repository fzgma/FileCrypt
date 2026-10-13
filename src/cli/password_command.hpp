#pragma once

namespace filecrypt::cli {
/// 解析密码生成选项，只向标准输出写入一行密码。
void generate_password_command(int argc, char** argv);
}
