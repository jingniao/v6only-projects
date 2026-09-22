#!/usr/bin/env bash
# 中文管理入口；源码运行依赖 Python 3，发行文件由 tools/build.py 生成。
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' '前置条件不满足：需要 Python 3.9 或更新版本。' >&2
    exit 3
fi
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export V6ONLY_ENTRY="$SOURCE_DIR/$(basename -- "${BASH_SOURCE[0]}")"
exec python3 -B "$SOURCE_DIR/lib/v6only.py" "$@"
