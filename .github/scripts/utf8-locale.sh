#!/usr/bin/env bash
# 由 Linux 构建与复验脚本加载；libarchive 需要 UTF-8 locale 解包 Unicode 名称。
filecrypt_utf8_locale=
while IFS= read -r candidate; do
    case "${candidate,,}" in
        *.utf8|*.utf-8)
            filecrypt_utf8_locale="$candidate"
            break
            ;;
    esac
done < <(locale -a)
if [[ -z "$filecrypt_utf8_locale" ]]; then
    echo '未找到 UTF-8 locale；请安装或生成 UTF-8 locale 后运行测试。' >&2
    exit 1
fi
export LANG="$filecrypt_utf8_locale"
export LC_ALL="$filecrypt_utf8_locale"
if [[ "$(locale charmap)" != UTF-8 ]]; then
    echo "无法启用 UTF-8 locale：$filecrypt_utf8_locale" >&2
    exit 1
fi
echo "测试 locale：$LC_ALL ($(locale charmap))"
