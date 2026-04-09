#!/usr/bin/env python3

import builtins
import importlib.util
import json
import math
import sys
import traceback

try:
    import resource
except ImportError:
    resource = None

try:
    import signal as _signal_module
except ImportError:
    _signal_module = None

import threading


# Maximum IPC message size (P3 fix): 1 MB
MAX_IPC_MESSAGE_BYTES = 1 * 1024 * 1024

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
    "pathlib",
    "shutil",
    "subprocess",
    "sys",
    "socket",
    "http",
    "requests",
    "signal",
    "multiprocessing",
    "threading",
    "code",
    "codeop",
    "compileall",
    "py_compile",
    "ast",
    "inspect",
    "gc",
    "pickle",
    "shelve",
    "marshal",
}


# P1: Builtins that are SAFE for sandboxed plugins
SAFE_BUILTINS = {
    # Types & constants
    "True": True,
    "False": False,
    "None": None,
    # Safe numeric/string types
    "int": int,
    "float": float,
    "complex": complex,
    "str": str,
    "bytes": bytes,
    "bytearray": bytearray,
    "bool": bool,
    # Collections
    "list": list,
    "tuple": tuple,
    "dict": dict,
    "set": set,
    "frozenset": frozenset,
    # Safe iteration / functional
    "range": range,
    "enumerate": enumerate,
    "zip": zip,
    "map": map,
    "filter": filter,
    "reversed": reversed,
    "sorted": sorted,
    "iter": iter,
    "next": next,
    "len": len,
    "min": min,
    "max": max,
    "sum": sum,
    "all": all,
    "any": any,
    "abs": abs,
    "round": round,
    "divmod": divmod,
    "pow": pow,
    # String/repr
    "repr": repr,
    "ascii": ascii,
    "chr": chr,
    "ord": ord,
    "hex": hex,
    "oct": oct,
    "bin": bin,
    "format": format,
    "hash": hash,
    "id": id,
    "isinstance": isinstance,
    "issubclass": issubclass,
    "callable": callable,
    "hasattr": hasattr,
    "print": print,
    # Exceptions (allow raising/catching)
    "Exception": Exception,
    "BaseException": BaseException,
    "ValueError": ValueError,
    "TypeError": TypeError,
    "KeyError": KeyError,
    "IndexError": IndexError,
    "AttributeError": AttributeError,
    "RuntimeError": RuntimeError,
    "StopIteration": StopIteration,
    "IOError": IOError,
    "OSError": OSError,
    "OverflowError": OverflowError,
    "ZeroDivisionError": ZeroDivisionError,
    "ImportError": ImportError,
    "NotImplementedError": NotImplementedError,
    "ArithmeticError": ArithmeticError,
    "LookupError": LookupError,
    "UnicodeError": UnicodeError,
    "UnicodeDecodeError": UnicodeDecodeError,
    "UnicodeEncodeError": UnicodeEncodeError,
    # P1: DELIBERATELY EXCLUDED (these enable sandbox escape):
    #   eval, exec, compile       - arbitrary code execution
    #   __import__                - bypass import guard
    #   getattr, setattr, delattr - attribute manipulation for introspection attacks
    #   globals, vars, locals     - namespace introspection
    #   type                      - metaclass manipulation
    #   open                      - file system access
    #   breakpoint                - debugger escape
    #   memoryview                - raw memory access
    #   dir                       - namespace enumeration for introspection chains
    #   property, classmethod, staticmethod - descriptor manipulation
}


# P1: Blocked attribute names that enable class introspection escape chains
BLOCKED_ATTRIBUTES = frozenset({
    "__subclasses__",
    "__bases__",
    "__mro__",
    "__class__",
    "__globals__",
    "__code__",
    "__func__",
    "__self__",
    "__dict__",
    "__builtins__",
    "__loader__",
    "__spec__",
    "__qualname__",
    "__wrapped__",
    "__reduce__",
    "__reduce_ex__",
})


def install_limits(timeout_ms):
    """Install resource limits using best available mechanism per platform."""
    cpu_seconds = max(1, int(math.ceil(timeout_ms / 1000.0)) + 1)
    memory_limit = 256 * 1024 * 1024

    # P2: Primary mechanism: POSIX resource limits (Linux)
    if resource is not None:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        except (OSError, ValueError):
            pass

        try:
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        except (OSError, ValueError):
            pass
    # P2: Fallback for macOS: signal.alarm for CPU timeout
    elif _signal_module is not None and hasattr(_signal_module, 'SIGALRM'):
        try:
            def _alarm_handler(signum, frame):
                raise SystemExit("Plugin exceeded CPU time limit")
            _signal_module.signal(_signal_module.SIGALRM, _alarm_handler)
            _signal_module.alarm(cpu_seconds)
        except (OSError, ValueError):
            pass
    # P2: Last resort fallback (Windows): threading.Timer kill switch
    else:
        def _timeout_kill():
            import os
            os._exit(137)  # Simulate SIGKILL exit code
        timer = threading.Timer(float(cpu_seconds), _timeout_kill)
        timer.daemon = True
        timer.start()


def install_environment(allowed_env):
    import os
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
            raise ImportError(f"import of '{root}' is blocked by the Rothalyx plugin sandbox policy")
        if level != 0 or root in allowlist:
            return original_import(name, globals, locals, fromlist, level)
        raise ImportError(f"import of '{root}' is blocked by the Rothalyx plugin sandbox")

    builtins.__import__ = guarded_import


def install_restricted_builtins():
    """P1: Replace __builtins__ with a restricted dict. This blocks eval/exec/compile/getattr
    and prevents introspection-based sandbox escape chains."""

    # Install the guarded import into the safe builtins
    restricted = dict(SAFE_BUILTINS)
    restricted["__import__"] = builtins.__import__  # Use the guarded version

    # P1: Install a sandboxed getattr that blocks introspection attributes
    _real_getattr = getattr

    def safe_getattr(obj, name, *default):
        if isinstance(name, str) and name in BLOCKED_ATTRIBUTES:
            raise AttributeError(
                f"access to '{name}' is blocked by the Rothalyx plugin sandbox"
            )
        if default:
            return _real_getattr(obj, name, default[0])
        return _real_getattr(obj, name)

    restricted["getattr"] = safe_getattr

    # Overwrite module-level builtins for all future code execution
    builtins.__dict__.clear()
    builtins.__dict__.update(restricted)


def load_plugin(path):
    spec = importlib.util.spec_from_file_location("rothalyx_plugin_sandboxed", path)
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
    install_restricted_builtins()

    try:
        plugin = load_plugin(plugin_path)
    except Exception as exc:
        emit({"ok": False, "error": f"plugin load failed: {exc}"})
        return 1

    for raw_line in sys.stdin:
        # P3: Enforce IPC message size limit
        if len(raw_line) > MAX_IPC_MESSAGE_BYTES:
            emit({"ok": False, "error": "IPC message exceeds maximum allowed size"})
            continue

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

            # P1: Block introspection-style hook names
            if hook_name.startswith("_"):
                emit({"ok": False, "error": f"hook name '{hook_name}' is blocked by sandbox policy"})
                continue

            payload = command.get("payload")
            hook = builtins.__dict__["getattr"](plugin, hook_name, None)
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

