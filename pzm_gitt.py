#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File auto-generated - pzm self-decryptor
import requests, struct, base64, json
from argon2.low_level import hash_secret_raw, Type
from ecdsa import VerifyingKey, NIST521p
from Crypto.Cipher import AES


import sys
import os
import hashlib
import threading
import time
import importlib
import importlib.util
import builtins
import types
import traceback
import marshal
import base64
import random
import string

# --- Cấu hình mặc định ---
DEFAULT_WATCH_INTERVAL = 3.0  # giây

# Danh sách module/tool thường thấy trong quá trình debug / reversing
SUSPICIOUS_MODULES = {
    "pydevd", "pdb", "frida", "r2pipe", "unicorn",
    "pwntools", "capstone", "angr", "gdb",
}

# --- Helpers ---

def _read_file_in_chunks(path, chunk_size=8192):
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk

def compute_file_sha256(path):
    """Tính SHA256 cho file path; trả về hex digest. Bảo đảm path tồn tại."""
    h = hashlib.sha256()
    for chunk in _read_file_in_chunks(path):
        h.update(chunk)
    return h.hexdigest()

def _target_main_path():
    """
    Lấy đường dẫn file chính để kiểm tra toàn vẹn:
    - Nếu chạy bằng python script: sys.argv[0] thường là script path
    - Nếu import như module, có thể truyền đường dẫn trực tiếp
    """
    try:
        arg0 = sys.argv[0]
        if arg0 and os.path.isfile(arg0):
            return os.path.abspath(arg0)
    except Exception:
        pass
    # fallback: module __main__
    try:
        import __main__
        if hasattr(__main__, "__file__"):
            return os.path.abspath(__main__.__file__)
    except Exception:
        pass
    return None

# --- Kiểm tra phát hiện debugger / tracer ---

def detect_sys_tracer():
    """Phát hiện trace bằng sys.gettrace(). Đây là kiểm tra cơ bản."""
    tracer = sys.gettrace()
    if tracer is not None:
        # Một số runner/coverage tools có thể đặt tracer; đó là tradeoff.
        return True, f"sys.gettrace() -> {tracer}"
    return False, ""

def detect_suspicious_modules():
    """Kiểm tra xem có module reverse/debug thường gặp đã được import không."""
    found = []
    for name in SUSPICIOUS_MODULES:
        if name in sys.modules:
            found.append(name)
    return (len(found) > 0), ", ".join(found)

def detect_tracerpid_linux():
    """
    Trên Linux, đọc /proc/self/status -> TracerPid (nếu > 0 có thể bị ptrace).
    Trả về False nếu không thể xác định (non-linux hoặc không có quyền).
    """
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        val = int(line.split()[1])
                        if val > 0:
                            return True, f"TracerPid={val}"
                        else:
                            return False, ""
    except Exception:
        pass
    return False, ""

def detect_parent_debugger():
    """
    Cố gắng phát hiện tên tiến trình cha (nếu hệ thống hỗ trợ).
    Cần try/except để tránh phụ thuộc psutil.
    """
    try:
        # Linux: đọc /proc/<ppid>/comm
        if hasattr(os, "getppid") and sys.platform.startswith("linux"):
            ppid = os.getppid()
            comm_path = f"/proc/{ppid}/comm"
            if os.path.exists(comm_path):
                with open(comm_path, "r") as f:
                    parent_name = f.read().strip()
                    suspicious_names = ("gdb", "lldb", "strace", "frida-server", "ida")
                    for s in suspicious_names:
                        if s in parent_name.lower():
                            return True, f"parent={parent_name}"
    except Exception:
        pass
    return False, ""

# --- Toàn vẹn (integrity) ---

def verify_integrity(expected_hash, target_path=None):
    """
    So sánh SHA256 của target_path (nếu None -> cố lấy sys.argv[0] hoặc __main__.__file__)
    với expected_hash.
    Trả về (ok: bool, msg: str)
    """
    if expected_hash is None:
        return True, "no expected_hash provided"
    if target_path is None:
        target_path = _target_main_path()
    if not target_path or not os.path.exists(target_path):
        return False, f"target file not found: {target_path}"
    try:
        current = compute_file_sha256(target_path)
        if current.lower() != expected_hash.lower():
            return False, f"hash mismatch: {current} != expected"
        return True, "hash ok"
    except Exception as e:
        return False, f"exception computing hash: {e}"

# --- Watchdog và hành động phản hồi ---

def react_to_tamper(reason):
    """Hành động khi phát hiện tamper: log rồi exit. Có thể tuỳ chỉnh (ví dụ: degrade tính năng)."""
    sys.stderr.write(f"[ANTI-CRACK] Tamper detected: {reason}\n")
    # Không thực hiện hành vi destructive. Chỉ exit an toàn.
    try:
        # Ghi traceback giúp debug logs (nếu có)
        traceback.print_stack(file=sys.stderr)
    except Exception:
        pass
    # Thoát chương trình
    sys.exit(1)

def _single_check(expected_hash=None, target_path=None):
    """Thực hiện một lượt kiểm tra; trả về (ok, reasons_list)"""
    reasons = []
    # 1) Integrity
    ok, msg = verify_integrity(expected_hash, target_path)
    if not ok:
        reasons.append(f"integrity: {msg}")

    # 2) sys tracer
    ok_tr, msg_tr = detect_sys_tracer()
    if ok_tr:
        reasons.append(f"debugger: {msg_tr}")

    # 3) suspicious modules
    ok_mod, msg_mod = detect_suspicious_modules()
    if ok_mod:
        reasons.append(f"suspicious_modules: {msg_mod}")

    # 4) linux TracerPid
    ok_tp, msg_tp = detect_tracerpid_linux()
    if ok_tp:
        reasons.append(f"ptrace: {msg_tp}")

    # 5) parent process name
    ok_pp, msg_pp = detect_parent_debugger()
    if ok_pp:
        reasons.append(f"parent_debugger: {msg_pp}")

    return (len(reasons) == 0), reasons

def start_watchdog(expected_hash=None, target_path=None, interval=DEFAULT_WATCH_INTERVAL, daemon=True):
    """
    Bắt một thread watchdog để kiểm tra định kỳ. Nếu phát hiện, gọi react_to_tamper.
    Trả về Thread object (đã start).
    """
    stop_event = threading.Event()

    def loop():
        while not stop_event.is_set():
            try:
                ok, reasons = _single_check(expected_hash, target_path)
                if not ok:
                    react_to_tamper("; ".join(reasons))
                    return
            except SystemExit:
                raise
            except Exception:
                # Không để watchdog crash app; chỉ in log
                sys.stderr.write("[ANTI-CRACK] watchdog exception\n")
            stop_event.wait(interval)

    t = threading.Thread(target=loop, name="anti_crack_watchdog", daemon=daemon)
    t._stop_event = stop_event  # attach để có thể dừng nếu cần
    t.start()
    return t

# --- Decorator / wrapper để bảo vệ entrypoint ---


def protect(entry_func=None, expected_hash=None, target_path=None, watch_interval=DEFAULT_WATCH_INTERVAL,
            lock_modules_list=None, lock_interval=1.0, harden_static_list=None, harden_key=None):
    """
    Nếu gọi như: protect(expected_hash="...")(main_func) -> decorator
    Hoặc: protect(main_func, expected_hash=...)
    Tuỳ chọn:
      - lock_modules_list = ['requests', 'urllib', 'httpx'] để tự động lock các module này trước khi main chạy.
      - harden_static_list = ['mymodule', 'requests'] để áp dụng anti-static measures cho các module này.
      - harden_key = bytes key dùng cho encode/decode (nếu None -> random nội bộ).
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Lấy target path nếu chưa có
            tp = target_path or _target_main_path()
            ok, reasons = _single_check(expected_hash, tp)
            if not ok:
                react_to_tamper("; ".join(reasons))
            # Start main watchdog
            start_watchdog(expected_hash=expected_hash, target_path=tp, interval=watch_interval)
            # Nếu có yêu cầu khóa modules, làm sớm nhất
            if lock_modules_list:
                try:
                    lock_modules(lock_modules_list, interval=lock_interval)
                except Exception:
                    # Đừng crash app nếu lock thất bại
                    sys.stderr.write("[ANTI-CRACK] lock_modules failed in protect\n")
            # Nếu có yêu cầu harden static, thực hiện
            if harden_static_list:
                try:
                    # nếu không có key, sinh ngẫu nhiên (sufficiently random cho mục đích encoding)
                    key = harden_key or _random_key()
                    anti_static_harden(harden_static_list, key=key, interval=lock_interval)
                except Exception:
                    sys.stderr.write("[ANTI-CRACK] anti_static_harden failed in protect\n")
            # Thực thi hàm chính
            return func(*args, **kwargs)
        # Giữ metadata
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    # Nếu được dùng như protect(main_func, expected_hash=...), hỗ trợ trực tiếp
    if callable(entry_func):
        return decorator(entry_func)
    return decorator

# --- Hàm tiện ích: tính hash file (dùng để compute trước khi phân phối) ---
def compute_and_print_target_hash(target_path=None):
    tp = target_path or _target_main_path()
    if not tp or not os.path.exists(tp):
        raise FileNotFoundError(f"target file not found: {tp}")
    print(f"Target file: {tp}")
    print("SHA256:", compute_file_sha256(tp))

# --- Generic module sealing (lock multiple modules) ---
# Structure:
# _module_seal_state = {
#   "orig_import": <callable>,
#   "orig_reload": <callable>,
#   "modules": { name: {sealed, sealed_module, original_module, snapshot} },
#   "watch_thread": Thread or None,
#   "stop_event": Event or None,
# }
_module_seal_state = {
    "orig_import": None,
    "orig_reload": None,
    "modules": {},
    "watch_thread": None,
    "stop_event": None,
}

class SealedModule(types.ModuleType):
    """Module proxy chỉ đọc, trả về attribute từ snapshot/real module nhưng chặn ghi/xóa."""
    def __init__(self, real_mod, public_map):
        super().__init__(getattr(real_mod, "__name__", "sealed_module"))
        # lưu trữ tham chiếu gốc để có thể kiểm tra/tái khôi phục
        object.__setattr__(self, "_real_mod", real_mod)
        object.__setattr__(self, "_public_map", public_map)
        object.__setattr__(self, "__sealed__", True)
        # forward common metadata
        try:
            self.__file__ = getattr(real_mod, "__file__", None)
            self.__path__ = getattr(real_mod, "__path__", None)
            self.__spec__ = getattr(real_mod, "__spec__", None)
        except Exception:
            pass

    def __getattr__(self, name):
        pm = object.__getattribute__(self, "_public_map")
        if name in pm:
            return pm[name]
        real = object.__getattribute__(self, "_real_mod")
        return getattr(real, name)

    def __setattr__(self, name, value):
        raise AttributeError("sealed module cannot be modified")

    def __delattr__(self, name):
        raise AttributeError("sealed module cannot be deleted")

    def __dir__(self):
        pm = object.__getattribute__(self, "_public_map")
        return list(pm.keys())

def _build_public_snapshot(mod):
    """Lấy các attribute công khai (không bắt đầu bằng '_') và lưu object + id để kiểm tra."""
    snapshot = {}
    if mod is None:
        return snapshot
    for name in dir(mod):
        if name.startswith("_"):
            continue
        try:
            obj = getattr(mod, name)
            snapshot[name] = {"obj": obj, "id": id(obj)}
        except Exception:
            # skip
            pass
    return snapshot

def _install_import_wrapper():
    """Wrap builtins.__import__ để khi import các module bị khóa, trả về sealed module từ sys.modules."""
    if _module_seal_state["orig_import"] is not None:
        return  # đã cài
    orig = builtins.__import__
    _module_seal_state["orig_import"] = orig

    def import_wrapper(name, globals=None, locals=None, fromlist=(), level=0):
        # Gọi import gốc
        mod = orig(name, globals, locals, fromlist, level)
        try:
            # Kiểm tra nếu import về modul bị khóa
            locked = set(_module_seal_state["modules"].keys())
            if name in locked:
                sm = _module_seal_state["modules"].get(name, {}).get("sealed_module")
                if sm is not None:
                    sys.modules[name] = sm
                    return sys.modules[name]
            # handle fromlist: nếu fromlist chứa tên module khóa, gắn sealed vào sys.modules
            if fromlist:
                for item in fromlist:
                    if item in locked:
                        sm = _module_seal_state["modules"].get(item, {}).get("sealed_module")
                        if sm is not None:
                            sys.modules[item] = sm
        except Exception:
            pass
        return mod

    builtins.__import__ = import_wrapper

def _install_reload_wrapper():
    """Wrap importlib.reload để chặn reload cho các module bị khóa."""
    if _module_seal_state["orig_reload"] is not None:
        return
    try:
        orig_reload = importlib.reload
    except Exception:
        orig_reload = None
    _module_seal_state["orig_reload"] = orig_reload

    def reload_wrapper(module):
        try:
            name = getattr(module, "__name__", None)
            if name in _module_seal_state["modules"]:
                raise RuntimeError(f"Reload of '{name}' is blocked by anti-crack lock")
        except Exception:
            pass
        if orig_reload is None:
            raise RuntimeError("original importlib.reload unavailable")
        return orig_reload(module)

    importlib.reload = reload_wrapper

def _modules_watchdog(interval):
    """Thread watchdog giám sát tất cả module đã khóa; nếu phát hiện thay đổi -> react_to_tamper."""
    stop_event = _module_seal_state.get("stop_event")
    while not (stop_event and stop_event.is_set()):
        try:
            modules_state = _module_seal_state.get("modules", {})
            for name, st in list(modules_state.items()):
                sealed_mod = st.get("sealed_module")
                orig_mod = st.get("original_module")
                snapshot = st.get("snapshot")
                if sealed_mod is None or snapshot is None:
                    continue
                # 1) Kiểm tra sys.modules[name] có phải sealed module không
                current = sys.modules.get(name)
                if current is None:
                    react_to_tamper(f"{name} missing from sys.modules")
                    return
                if not getattr(current, "__sealed__", False):
                    react_to_tamper(f"{name} module replaced in sys.modules (not sealed)")
                    return
                # 2) Kiểm tra attributes: id hiện tại của từng attribute public có trùng snapshot ko
                for attr, info in snapshot.items():
                    try:
                        cur_obj = getattr(orig_mod, attr, None)
                        if cur_obj is None:
                            react_to_tamper(f"{name} attribute removed: {attr}")
                            return
                        if id(cur_obj) != info["id"]:
                            react_to_tamper(f"{name} attribute changed: {attr}")
                            return
                    except Exception:
                        react_to_tamper(f"exception while checking {name} attribute: {attr}")
                        return
        except SystemExit:
            raise
        except Exception:
            # Không để watchdog crash app
            sys.stderr.write("[ANTI-CRACK] modules_watchdog exception\n")
        # chờ interval
        if stop_event:
            stop_event.wait(interval)
        else:
            time.sleep(interval)

def lock_modules(module_names, interval=1.0):
    """
    Khóa/niêm phong danh sách module:
    - Nếu module đã import, sẽ tạo sealed proxy và đặt vào sys.modules
    - Nếu module chưa có, tạo dummy sealed module để chặn import/reload sau này
    - Cài wrapper cho builtins.__import__ và importlib.reload
    - Bật một watchdog chung để kiểm tra định kỳ (interval giây)
    Trả về True/False
    """
    try:
        if not module_names:
            return True
        # ensure dict entries exist
        for name in module_names:
            if name in _module_seal_state["modules"] and _module_seal_state["modules"][name].get("sealed"):
                continue
            # Try import module if present
            real_mod = None
            try:
                real_mod = importlib.import_module(name)
            except Exception:
                real_mod = None  # module not installed yet
            snapshot = _build_public_snapshot(real_mod) if real_mod is not None else {}
            real_mod_for_proxy = real_mod if real_mod is not None else types.ModuleType(name)
            sealed = SealedModule(real_mod_for_proxy, {k: v["obj"] for k, v in snapshot.items()})
            # Place sealed in sys.modules
            sys.modules[name] = sealed
            # Save state
            _module_seal_state["modules"][name] = {
                "sealed": True,
                "sealed_module": sealed,
                "original_module": real_mod_for_proxy,
                "snapshot": snapshot,
            }
        # install wrappers
        _install_import_wrapper()
        _install_reload_wrapper()
        # start watchdog if not started
        if _module_seal_state.get("watch_thread") is None:
            stop_event = threading.Event()
            _module_seal_state["stop_event"] = stop_event
            t = threading.Thread(target=_modules_watchdog, args=(interval,), name="modules_seal_watchdog", daemon=True)
            _module_seal_state["watch_thread"] = t
            t.start()
        sys.stderr.write(f"[ANTI-CRACK] locked modules: {list(_module_seal_state['modules'].keys())}\n")
        return True
    except Exception as e:
        sys.stderr.write(f"[ANTI-CRACK] lock_modules failed: {e}\n")
        return False

def unlock_modules():
    """
    Thử khôi phục lại import/reload gốc và module gốc nếu có.
    WARNING: chỉ dùng trong dev/test.
    """
    try:
        # Stop watchdog
        se = _module_seal_state.get("stop_event")
        if se:
            se.set()
        # Restore builtins.__import__
        if _module_seal_state.get("orig_import") is not None:
            builtins.__import__ = _module_seal_state["orig_import"]
            _module_seal_state["orig_import"] = None
        # Restore importlib.reload
        if _module_seal_state.get("orig_reload") is not None:
            importlib.reload = _module_seal_state["orig_reload"]
            _module_seal_state["orig_reload"] = None
        # Restore modules to original_module if available
        for name, st in list(_module_seal_state.get("modules", {}).items()):
            orig = st.get("original_module")
            if orig is not None:
                sys.modules[name] = orig
            else:
                # remove dummy if we created one
                if name in sys.modules:
                    try:
                        del sys.modules[name]
                    except Exception:
                        pass
        # reset state
        _module_seal_state["modules"] = {}
        _module_seal_state["watch_thread"] = None
        _module_seal_state["stop_event"] = None
        sys.stderr.write("[ANTI-CRACK] modules unlocked (dev only)\n")
        return True
    except Exception as e:
        sys.stderr.write(f"[ANTI-CRACK] unlock_modules failed: {e}\n")
        return False

# -----------------------------
# Anti static analysis helpers
# -----------------------------

def _random_key(length=16):
    return bytes(''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length)), 'utf-8')

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encode_secret_string(s: str, key: bytes) -> str:
    """Mã hoá chuỗi thành base64(xor(bytes, key))."""
    b = s.encode('utf-8')
    xb = _xor_bytes(b, key)
    return base64.b64encode(xb).decode('ascii')

def decode_secret_string(encoded: str, key: bytes) -> str:
    try:
        xb = base64.b64decode(encoded.encode('ascii'))
        b = _xor_bytes(xb, key)
        return b.decode('utf-8')
    except Exception:
        return ""

class SecretString:
    """Wrapper giữ chuỗi mã hoá; chỉ giải mã khi cần."""
    __slots__ = ("_enc", "_key")
    def __init__(self, enc, key):
        self._enc = enc
        self._key = key
    def reveal(self):
        return decode_secret_string(self._enc, self._key)
    def __str__(self):
        return self.reveal()
    def __repr__(self):
        return "<secret>"

def _make_lazy_function_from_code(code_bytes_b64, globals_dict, name=None):
    """Tạo một hàm lazy: khi lần đầu được gọi, sẽ load code object từ base64(marshal.dumps(code)) rồi bind."""
    def loader_wrapper(*args, **kwargs):
        # on first call, replace wrapper in globals with real function
        # decode marshal
        try:
            cb = base64.b64decode(code_bytes_b64.encode('ascii'))
            code_obj = marshal.loads(cb)
            real_fn = types.FunctionType(code_obj, globals_dict, name or code_obj.co_name)
            # replace in caller module globals so subsequent calls are direct
            globals_dict[real_fn.__name__] = real_fn
            return real_fn(*args, **kwargs)
        except Exception as e:
            # If something wrong, raise to surface error rather than silent failure
            raise
    # preserve some metadata
    loader_wrapper.__name__ = name or "lazy_fn"
    loader_wrapper.__doc__ = None
    return loader_wrapper

def _marshall_function_code(fn):
    """Return base64 of marshal.dumps(fn.__code__)."""
    try:
        cb = marshal.dumps(fn.__code__)
        return base64.b64encode(cb).decode('ascii')
    except Exception:
        return None

def _replace_function_with_lazy(module, fn_name, key=None):
    """Nếu module có function fn_name, thay bằng wrapper lazy (marshalled code) để giảm footprint tĩnh."""
    try:
        if not hasattr(module, fn_name):
            return False
        fn = getattr(module, fn_name)
        if not isinstance(fn, types.FunctionType):
            return False
        b64 = _marshall_function_code(fn)
        if not b64:
            return False
        # create lazy wrapper using module.__dict__ as globals
        wrapper = _make_lazy_function_from_code(b64, module.__dict__, name=fn.__name__)
        module.__dict__[fn_name] = wrapper
        return True
    except Exception:
        return False

def _obfuscate_module_strings(module, key):
    """Thay thế các chuỗi công khai trên module thành SecretString (mã hoá) để giảm dấu vết tĩnh."""
    try:
        for name in dir(module):
            if name.startswith("_"):
                continue
            try:
                val = getattr(module, name)
                if isinstance(val, str) and len(val) > 0 and len(val) < 4096:
                    enc = encode_secret_string(val, key)
                    setattr(module, name, SecretString(enc, key))
            except Exception:
                # tránh phá module
                continue
        return True
    except Exception:
        return False

def _hide_module_metadata(module):
    """Ẩn metadata module (giảm thông tin cho static analysis) - set __file__/__spec__/__loader__/__cached__."""
    try:
        if hasattr(module, "__file__"):
            try:
                module.__file__ = None
            except Exception:
                pass
        for attr in ("__spec__", "__loader__", "__cached__"):
            try:
                if hasattr(module, attr):
                    setattr(module, attr, None)
            except Exception:
                pass
        return True
    except Exception:
        return False

def _change_functions_co_filename(module, fake_prefix=None):
    """
    Thay đổi co_filename của các function trong module để traceback/static mapping khó theo dõi.
    Lưu ý: tái tạo code objects; giữ các tham số/bytecode giống nguyên bản, chỉ đổi co_filename.
    """
    changed = 0
    try:
        for name in dir(module):
            if name.startswith("_"):
                continue
            try:
                obj = getattr(module, name)
                if isinstance(obj, types.FunctionType):
                    code = obj.__code__
                    # Build new code object with changed co_filename.
                    fake_filename = (fake_prefix or "<hidden>") + "/" + obj.__name__ + ".py"
                    # construct new code object preserving all but co_filename
                    # CodeType signature varies by Python version; handle common variants
                    new_code = None
                    try:
                        # Python 3.8+ has replace() method on code objects
                        new_code = code.replace(co_filename=fake_filename)
                    except Exception:
                        # Fallback: reconstruct manually (best-effort)
                        try:
                            new_code = types.CodeType(
                                code.co_argcount,
                                code.co_posonlyargcount if hasattr(code, "co_posonlyargcount") else 0,
                                code.co_kwonlyargcount,
                                code.co_nlocals,
                                code.co_stacksize,
                                code.co_flags,
                                code.co_code,
                                code.co_consts,
                                code.co_names,
                                code.co_varnames,
                                fake_filename,
                                code.co_name,
                                code.co_firstlineno,
                                code.co_lnotab,
                                code.co_freevars,
                                code.co_cellvars
                            )
                        except Exception:
                            new_code = None
                    if new_code:
                        try:
                            new_fn = types.FunctionType(new_code, obj.__globals__, obj.__name__, obj.__defaults__, obj.__closure__)
                            new_fn.__dict__.update(getattr(obj, "__dict__", {}))
                            module.__dict__[name] = new_fn
                            changed += 1
                        except Exception:
                            pass
            except Exception:
                continue
    except Exception:
        pass
    return changed

def detect_static_tools_in_fs():
    """
    Tìm các công cụ decompiler/static trong hệ thống (heuristic).
    Mở rộng: kiểm tra
      - tên executable trong PATH (uncompyle6, decompyle3, pycdc, pyinstxtractor, compile6, decompile3,...)
      - presence via importlib.util.find_spec (các package pip đã cài)
      - hiện diện trong sys.modules (đã được import)
      - file/directory có tên tool trong thư mục làm việc (cwd) hoặc site-packages
    Trả về (found: bool, msg: str)
    """
    suspicious_names = [
        "uncompyle6", "decompyle3", "pycdc", "pyinstxtractor",
        "uncompyle", "decompiler", "compile6", "decompile3",
        "pyinstxtractor", "pycdc", "easy_install", "decompyle",
        "pydevd", "pycdc", "pyinstxtractor"
    ]
    checked = []

    # 1) Kiểm tra sys.modules nhanh
    try:
        for nm in suspicious_names:
            if nm in sys.modules:
                return True, f"module imported in sys.modules: {nm}"
    except Exception:
        pass

    # 2) Kiểm tra importable packages (installed via pip) bằng importlib.util.find_spec
    try:
        for nm in suspicious_names:
            try:
                spec = importlib.util.find_spec(nm)
                if spec is not None:
                    return True, f"package present (find_spec): {nm} -> {getattr(spec, 'origin', '')}"
            except Exception:
                continue
    except Exception:
        pass

    # 3) Kiểm tra executables trong PATH
    try:
        paths = os.environ.get("PATH", "").split(os.pathsep)
        for p in paths:
            if not p:
                continue
            for nm in suspicious_names:
                # look for exact name and name + .exe
                try:
                    f1 = os.path.join(p, nm)
                    f2 = os.path.join(p, nm + ".exe")
                    if os.path.exists(f1) or os.path.exists(f2):
                        return True, f"tool executable found in PATH: {f1 if os.path.exists(f1) else f2}"
                except Exception:
                    continue
    except Exception:
        pass

    # 4) Kiểm tra site-packages / dist-packages tree (heuristic)
    try:
        # attempt to detect common site-packages dirs
        site_dirs = set()
        # sys.path often contains site-packages paths
        for p in sys.path:
            if p and ("site-packages" in p or "dist-packages" in p or "lib" in p):
                site_dirs.add(p)
        for sd in list(site_dirs):
            try:
                for nm in suspicious_names:
                    # check directory or egg/dist-info starting with nm
                    candidate_dir = os.path.join(sd, nm)
                    candidate_py = os.path.join(sd, nm + ".py")
                    if os.path.exists(candidate_dir) or os.path.exists(candidate_py):
                        return True, f"tool found in site-packages: {os.path.join(sd, nm)}"
                    # check for distribution metadata
                    for suff in (f"{nm}-", f"{nm}_"):
                        for item in os.listdir(sd):
                            if item.startswith(nm) or nm in item:
                                return True, f"possible package metadata in site-packages: {os.path.join(sd, item)}"
            except Exception:
                continue
    except Exception:
        pass

    # 5) Kiểm tra thư mục làm việc hiện tại (cwd) và cây con để phát hiện file tên tool
    try:
        cwd = os.getcwd()
        max_depth = 3
        for root, dirs, files in os.walk(cwd):
            depth = root[len(cwd):].count(os.sep)
            if depth > max_depth:
                # giới hạn độ sâu để performance
                continue
            for nm in suspicious_names:
                # tìm file hoặc folder chứa tên
                for f in files:
                    if nm in f.lower():
                        return True, f"tool file found in cwd tree: {os.path.join(root, f)}"
                for d in dirs:
                    if nm in d.lower():
                        return True, f"tool dir found in cwd tree: {os.path.join(root, d)}"
    except Exception:
        pass

    # 6) Fallback: không tìm thấy
    return False, ""

def anti_static_harden(module_names, key=None, interval=1.0, apply_lazy=True, change_filenames=True):
    """
    Áp dụng tập hợp kỹ thuật làm khó phân tích tĩnh cho các module:
      - Ẩn metadata module (__file__/__spec__/__loader__/__cached__)
      - Mã hoá chuỗi công khai (SecretString)
      - Thay các function bằng lazy loader (marshal) để giảm dấu vết tĩnh (tuỳ chọn)
      - Thay đổi code.co_filename để traceback kém hữu ích (tuỳ chọn)
      - Bật watchdog heuristic phát hiện công cụ phân tích tĩnh (mở rộng)
    Gọi càng sớm càng tốt.
    Trả về True/False.
    """
    try:
        if key is None:
            key = _random_key()
        for name in module_names:
            try:
                mod = None
                try:
                    mod = importlib.import_module(name)
                except Exception:
                    # nếu chưa có, tạo dummy module để chặn import sau này
                    mod = types.ModuleType(name)
                    sys.modules[name] = mod
                # hide metadata
                _hide_module_metadata(mod)
                # obfuscate strings
                _obfuscate_module_strings(mod, key)
                # replace functions with lazy loaders
                if apply_lazy:
                    for attr in dir(mod):
                        if attr.startswith("_"):
                            continue
                        try:
                            # chỉ lazy các function có size/complexity vừa phải
                            obj = getattr(mod, attr)
                            if isinstance(obj, types.FunctionType):
                                _replace_function_with_lazy(mod, attr, key=key)
                        except Exception:
                            continue
                # change co_filename
                if change_filenames:
                    _change_functions_co_filename(mod, fake_prefix="<hidden_static>")
            except Exception:
                continue
        # start a light watchdog to detect static-analysis tools presence (heuristic)
        se = threading.Event()
        def _static_detect_loop():
            while not se.is_set():
                try:
                    found, msg = detect_static_tools_in_fs()
                    if found:
                        react_to_tamper("static_tool_detected: " + msg)
                        return
                except SystemExit:
                    raise
                except Exception:
                    pass
                se.wait(interval)
        t = threading.Thread(target=_static_detect_loop, name="anti_static_watchdog", daemon=True)
        t.start()
        # store event so caller can stop if needed (not exposed here, dev-only)
        return True
    except Exception as e:
        sys.stderr.write(f"[ANTI-CRACK] anti_static_harden failed: {e}\n")
        return False

# End of anti_crack.py


META = {
  "enc_id": "64127208",
  "api_url": "https://api-l7k1.onrender.com/data",
  "salt_b64": "v5qiltkda9j/WBvjYKLODQ==",
  "nonce_b64": "MlCLcTjK+FAnnVS3",
  "tag_b64": "I77TnCrlESmmF9q1bcUcQw==",
  "cipher_b64": "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",
  "public_pem": "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAXmeiJRb/4bvAZcjm+j53dEphey+igaKH0YffODHn\nSQt4Jddc+OTWhMo5KbavG2nYYTsV6pc/HcNJmNhsXgYEzzUAKadAyK07qMqPr4JK/a/8Kp1sHDXb\ndQNbQ2SyNjEiTed2ON1YrC5/N2ldGlBk+x3URCNcefdIPYEfhQsvnxzgTik=\n-----END PUBLIC KEY-----\n"
}
def from_bitstring(s: str) -> bytes:
    pad = (8 - (len(s) % 8)) % 8
    if pad:
        s = s + ("0"*pad)
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))

def find_meta_from_api(enc_id, api_url):
    try:
        r = requests.get(api_url, timeout=10)
        r.raise_for_status()
        arr = r.json()
        if not isinstance(arr, list):
            return None
        for obj in arr:
            if isinstance(obj, dict) and obj.get("enc_id") == enc_id:
                bits = obj.get("meta_bits")
                if isinstance(bits, str):
                    return bits
    except Exception as e:
        print("Lỗi khi lấy metadata từ API:", e)
    return None

def main():
    enc_id = META["enc_id"]
    api_url = META["api_url"]
    bits = find_meta_from_api(enc_id, api_url)
    if not bits:
        print("Không tìm thấy enc_id trên API hoặc error.")
        return
    raw = from_bitstring(bits)
    # header 3 * uint32
    if len(raw) < 12:
        print("Meta không hợp lệ")
        return
    a,b,c = struct.unpack(">III", raw[:12])
    off = 12
    base_key = raw[off:off+a]; off += a
    sig_plain = raw[off:off+b]; off += b
    sig_cipher = raw[off:off+c]; off += c

    # phái sinh key qua Argon2id (phải trùng với cách tạo file encryptor)
    salt = base64.b64decode(META["salt_b64"])
    enc_key = hash_secret_raw(base_key, salt, time_cost=2, memory_cost=65536, parallelism=1, hash_len=32, type=Type.ID)

    # giải mã AES-GCM
    nonce = base64.b64decode(META["nonce_b64"])
    tag = base64.b64decode(META["tag_b64"])
    cipher_b = base64.b64decode(META["cipher_b64"])
    try:
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(cipher_b, tag)
    except Exception as e:
        print("Giải mã thất bại:", e)
        return

    # verify signatures
    vk = VerifyingKey.from_pem(META["public_pem"])
    try:
        vk.verify(sig_plain, plaintext)
    except Exception as e:
        print("Chữ ký plaintext không hợp lệ:", e)
        return
    try:
        vk.verify(sig_cipher, nonce + cipher_b + tag)
    except Exception as e:
        print("Chữ ký ciphertext không hợp lệ:", e)
        return

    # exec
    try:
        exec(plaintext.decode('utf-8'), globals())
    except Exception as e:
        print("Lỗi khi chạy code giải mã:", e)

if __name__ == "__main__":
    main()
