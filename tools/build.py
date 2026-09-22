#!/usr/bin/env python3
"""生成确定性的单文件 Bash 入口，仍依赖系统 Python 3。"""
import hashlib
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/lib/v6only.py").read_text(encoding="utf-8")
start = source.index("# BEGIN BACKEND LOADER")
end = source.index("# END BACKEND LOADER") + len("# END BACKEND LOADER")
# 只内嵌受版本管理的源码，不把域名或用户参数作为 Python 代码执行。
embedded = "import types\n"
for name, path in {"SINGBOX": "backends/singbox.py", "DNSMASQ": "backends/dnsmasq.py", "TRANSACTIONS": "lib/transactions.py",
                   "HOST": "lib/host.py", "OBSERVABILITY": "lib/observability.py", "RUNTIME": "lib/runtime.py"}.items():
    module = (ROOT / "src" / path).read_text(encoding="utf-8")
    embedded += name + " = types.ModuleType('v6only_" + name.lower() + "')\nexec(compile(" + repr(module) + ", '<内嵌 " + name + ">', 'exec'), " + name + ".__dict__)\n"
source = source[:start] + embedded + source[end:]
delimiter = "V6ONLY_PY_" + hashlib.sha256(source.encode()).hexdigest()
# Python 从发行文件自身读取静态载荷，避免 Bash 大型 heredoc 在 dry-run 时创建临时文件。
header = '''#!/usr/bin/env bash
# 由 tools/build.py 自动生成；运行依赖 Linux、Bash 和 Python 3.9+。
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\\n' '前置条件不满足：需要 Python 3.9 或更新版本。' >&2
    exit 3
fi
export V6ONLY_ENTRY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
'''
bootstrap = ("import hashlib,os,sys; from pathlib import Path; "
             "path=os.environ['V6ONLY_ENTRY']; "
             "payload=Path(path).read_text(encoding='utf-8').split('\\n# V6ONLY_PAYLOAD\\n',1)[1]; "
             "source,marker,_=payload.rsplit('\\n',2); "
             "expected='V6ONLY_PY_'+hashlib.sha256(source.encode()).hexdigest(); "
             "sys.exit('发行文件载荷摘要不匹配') if marker != expected else None; "
             "sys.argv[0]=path; globals()['__file__']=path; exec(compile(source,path,'exec'))")
artifact = header + "exec python3 -B -c " + shlex.quote(bootstrap) + ' "$@"\n' + ": <<'" + delimiter + "'\n# V6ONLY_PAYLOAD\n" + source + "\n" + delimiter + "\n"
destination = ROOT / "dist/v6only"
destination.parent.mkdir(exist_ok=True)
with destination.open("w", encoding="utf-8", newline="\n") as stream:
    stream.write(artifact)
destination.chmod(0o755)
print(hashlib.sha256(artifact.encode()).hexdigest() + "  dist/v6only")
