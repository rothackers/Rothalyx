#!/usr/bin/env python3

import builtins
import importlib.util
import json
import math
import os
import sys
import traceback

try:
    import resource
except ImportError:
    resource = None


SAFE_IMPORTS = {
    "_collections_abc",
    "_frozen_importlib",
    "_frozen_importlib_external",
    "_io",
    "builtins",
    "collections",
    "codecs",
    "encodings",
    "functools",
    "genericpath",
    "io",
    "itertools",
    "json",
    "linecache",
    "math",
    "pathlib",
    "posix",
    "posixpath",
    "re",
    "string",
    "token",
    "tokenize",
    "types",
    "warnings",
    "zipimport",
}

DENIED_IMPORTS = {
    "ctypes",
    "importlib",
    "os",
    "shutil",
    "subprocess",
    "sys",
}


def install_limits(timeout_ms):
    if resource is None:
        return

    cpu_seconds = max(1, int(math.ceil(timeout_ms / 1000.0)) + 1)
    memory_limit = 256 * 1024 * 1024

    try:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    except (OSError, ValueError):
        pass

    try:
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
    except (OSError, ValueError):
        pass


def install_environment(allowed_env):
    preserved = {key: value for key, value in os.environ.items() if key in allowed_env}
    os.environ.clear()
    os.environ.update(preserved)


def install_import_guard(allowed_imports):
    original_import = builtins.__import__
    allowlist = set(SAFE_IMPORTS)
    allowlist.update(root for root in allowed_imports if root not in DENIED_IMPORTS)

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        root = name.split(".", 1)[0]
        if root in DENIED_IMPORTS:
            raise ImportError(f"import of '{root}' is blocked by the Zara plugin sandbox policy")
        if level != 0 or root in allowlist:
            return original_import(name, globals, locals, fromlist, level)
        raise ImportError(f"import of '{root}' is blocked by the Zara plugin sandbox")

    builtins.__import__ = guarded_import


def load_plugin(path):
    spec = importlib.util.spec_from_file_location("zara_plugin_sandboxed", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load plugin spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def emit(message):
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main():
    if len(sys.argv) != 5:
        emit({"ok": False, "error": "usage: plugin_host.py <plugin.py> <allowed_imports_json> <allowed_env_json> <timeout_ms>"})
        return 2

    plugin_path = sys.argv[1]
    allowed_imports = set(json.loads(sys.argv[2]))
    allowed_env = set(json.loads(sys.argv[3]))
    timeout_ms = int(sys.argv[4])

    denied = sorted(root for root in allowed_imports if root.split(".", 1)[0] in DENIED_IMPORTS)
    if denied:
        emit({"ok": False, "error": "sandbox policy rejects allow_imports entries: " + ", ".join(denied)})
        return 2

    install_limits(timeout_ms)
    install_environment(allowed_env)
    install_import_guard(allowed_imports)

    try:
        plugin = load_plugin(plugin_path)
    except Exception as exc:
        emit({"ok": False, "error": f"plugin load failed: {exc}"})
        return 1

    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        try:
            command = json.loads(raw_line)
            if command.get("command") == "shutdown":
                emit({"ok": True, "shutdown": True})
                return 0

            if command.get("command") != "call":
                emit({"ok": False, "error": "unsupported sandbox command"})
                continue

            hook_name = command.get("hook", "")
            payload = command.get("payload")
            hook = getattr(plugin, hook_name, None)
            if hook is None:
                emit({"ok": True, "missing": True})
                continue

            hook(payload)
            emit({"ok": True})
        except Exception as exc:
            emit({"ok": False, "error": str(exc), "traceback": traceback.format_exc(limit=4)})

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
