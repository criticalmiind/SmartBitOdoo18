import os
import ctypes
from ctypes import wintypes

# ---- Your device config (edit if needed) ----
HOST = "123.123.123.14"
PORT = 8123
FISCAL_PASSWORD = "krLGfzRh"
DEPARTMENT = 1          # used by some login variants
CASHIER_ID = 3
CASHIER_PIN = "4321"
DLL_PATH = os.path.join(os.path.dirname(__file__), "hdm", "HDMPrint.dll")

# ---- Likely export names (adjust if DLL uses different names) ----
CONNECT_NAMES = ["HDM_Initialize", "HDM_Connect", "HDM_ConnectTCP", "Initialize", "Connect", "ConnectTCP"]
LOGIN_NAMES = ["HDM_LoginEx", "HDM_Login", "LoginEx", "Login", "HDM_CashierLogin"]
DEPS_NAMES  = ["HDM_GetDepartmentsJSON", "HDM_GetDepartmentList", "HDM_GetDepartments",
               "GetDepartmentsJSON", "GetDepartmentList", "GetDepartments"]

# Try wide (W) first, then ANSI (A), then unsuffixed
SUFFIXES = ["W", "A", ""]

def _load_dll(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"HDM DLL not found at: {path}")
    try:
        return ctypes.WinDLL(path)
    except Exception:
        return ctypes.CDLL(path)

def _resolve(lib, base_names):
    """Return (callable, is_wide) for the first symbol that exists, trying W/A/unsuffixed."""
    tried = []
    for base in base_names:
        for suf in SUFFIXES:
            name = f"{base}{suf}"
            try:
                fn = getattr(lib, name)
                return fn, (suf == "W")
            except AttributeError:
                tried.append(name)
                continue
    raise AttributeError("None of these functions were found in HDMPrint.dll: " + ", ".join(tried))

def connect(lib):
    fn, wide = _resolve(lib, CONNECT_NAMES)
    fn.restype = ctypes.c_int
    # Prefer signatures: (wchar*, uint16, int) or (wchar*, uint16)
    if wide:
        for sig in ([wintypes.LPCWSTR, ctypes.c_uint16, ctypes.c_int],
                    [wintypes.LPCWSTR, ctypes.c_uint16]):
            try:
                fn.argtypes = sig
                args = [HOST, PORT] + ([10000] if len(sig) == 3 else [])
                rc = fn(*args)
                if isinstance(rc, int) and rc < 0:
                    continue
                return
            except Exception:
                continue
    else:
        host_b = HOST.encode("utf-8")
        for sig in ([ctypes.c_char_p, ctypes.c_uint16, ctypes.c_int],
                    [ctypes.c_char_p, ctypes.c_uint16]):
            try:
                fn.argtypes = sig
                args = [host_b, PORT] + ([10000] if len(sig) == 3 else [])
                rc = fn(*args)
                if isinstance(rc, int) and rc < 0:
                    continue
                return
            except Exception:
                continue
    raise RuntimeError("Connect failed for all tried signatures")

def login_if_needed(lib):
    """Some DLLs require login; others let you read departments with just the fiscal password.
       We try a few common signatures; if all fail, we just skip login (not fatal)."""
    try:
        fn, wide = _resolve(lib, LOGIN_NAMES)
    except AttributeError:
        # No login export — many DLLs don’t require it for departments.
        return

    fn.restype = ctypes.c_int
    str_t = wintypes.LPCWSTR if wide else ctypes.c_char_p

    trials = [
        # (cashier, pin, password)
        ([ctypes.c_int, str_t, str_t], (CASHIER_ID, CASHIER_PIN, FISCAL_PASSWORD)),
        # (password, cashier, pin)
        ([str_t, ctypes.c_int, str_t], (FISCAL_PASSWORD, CASHIER_ID, CASHIER_PIN)),
        # (department, cashier, pin, password)
        ([ctypes.c_int, ctypes.c_int, str_t, str_t], (DEPARTMENT, CASHIER_ID, CASHIER_PIN, FISCAL_PASSWORD)),
    ]

    for argtypes, args in trials:
        try:
            fn.argtypes = argtypes
            call_args = []
            for a, t in zip(args, argtypes):
                if t == str_t and not wide:
                    call_args.append(a.encode("utf-8"))
                else:
                    call_args.append(a)
            rc = fn(*call_args)
            if not isinstance(rc, int) or rc >= 0:
                return
        except Exception:
            continue
    # If login fails everywhere, we proceed anyway — departments may still work without it.

def get_departments(lib):
    fn, wide = _resolve(lib, DEPS_NAMES)

    # Two common patterns:
    # 1) int GetDepartments*(wchar*/char* outBuf, int outLen)   -> rc==0 success
    # 2) const wchar_t*/char* GetDepartments*()                 -> returns pointer
    # We try buffer style first, then no-arg return-pointer style.

    # Try buffer
    try:
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_void_p, ctypes.c_int]
        out_len = 64 * 1024
        buf = ctypes.create_unicode_buffer(out_len) if wide else ctypes.create_string_buffer(out_len)
        rc = fn(buf, out_len)
        if isinstance(rc, int) and rc >= 0:
            return buf.value if wide else buf.value.decode("utf-8", "ignore")
    except Exception:
        pass

    # Try return-pointer
    try:
        fn.argtypes = []
        fn.restype = ctypes.c_wchar_p if wide else ctypes.c_char_p
        s = fn()
        if s:
            return s if wide else s.decode("utf-8", "ignore")
    except Exception:
        pass

    raise RuntimeError("GetDepartments call failed (both buffer and pointer forms).")

def main():
    if os.name != "nt":
        raise SystemExit("This script requires Windows.")
    lib = _load_dll(DLL_PATH)
    print("[HDM] DLL loaded:", DLL_PATH)

    print(f"[HDM] Connecting to {HOST}:{PORT} …")
    connect(lib)
    print("[HDM] Connected.")

    print("[HDM] Trying login (optional) …")
    login_if_needed(lib)
    print("[HDM] Login step done (or skipped).")

    print("[HDM] Fetching departments …")
    deps = get_departments(lib)
    print("\n=== Departments (raw) ===")
    print(deps)

if __name__ == "__main__":
    main()
