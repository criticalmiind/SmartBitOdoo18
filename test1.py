"""
HDM via HDMPrint.dll – Python wrapper & demo

What this script does
- Loads `HDMPrint.dll` from the same folder (works for either a .NET assembly or a native DLL).
- Tries a .NET path first (pythonnet / clr). If unavailable or the DLL is native, falls back to ctypes.
- Attempts to: Connect → Login → Fetch Departments → Fetch Device Info → Print results.
- If exact method names differ in your DLL, the script prints out discovered methods and
  uses name heuristics. You can tweak CANDIDATES_* lists below.

Prereqs
- Put `HDMPrint.dll` next to this script, or set DLL_PATH.
- If `HDMPrint.dll` is a .NET assembly, install pythonnet:  pip install pythonnet
- Run:  python hdm_via_HDMPrint_dll.py

Edit these credentials/config to match your device.
"""

import os
import sys
import json
import ctypes
import platform
from typing import Any, Callable, Dict, List, Optional, Tuple

# ================== USER CONFIG (from your message) ==================
HOST = "123.123.123.14"
PORT = 8123
DEPARTMENT = 1
FISCAL_PASSWORD = "krLGfzRh"
CASHIER_ID = 3
CASHIER_PIN = "4321"

# Path to HDMPrint.dll (default: same folder)
DLL_PATH = os.path.join(os.path.dirname(__file__), "HDMPrint.dll")

# ================== NAME CANDIDATES (adjust if needed) ===============
CANDIDATES_CONNECT = [
    "ConnectTCP", "Connect", "OpenTCP", "Open", "Init", "Initialize"
]
CANDIDATES_LOGIN = [
    "Login", "LogIn", "SignIn", "Authorize", "Auth"
]
CANDIDATES_DEPARTMENTS = [
    "GetDepartments", "GetDepartmentList", "Departments", "FetchDepartments"
]
CANDIDATES_DEVICE_INFO = [
    "GetDeviceInfo", "DeviceInfo", "GetInfo", "ReadDeviceInfo"
]
CANDIDATES_DISCONNECT = [
    "Disconnect", "Close", "Shutdown"
]

# For native DLLs we try common prefixes/suffixes and A/W variants
NATIVE_NAME_PREFIXES = ["", "HDM_", "Hdm", "hdm_"]
NATIVE_SUFFIXES = ["", "A", "W"]  # A=ANSI, W=Wide

# ================== UTILITIES ========================================

def debug(msg: str):
    print(f"[HDM] {msg}")


def pretty(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(obj)


# ================== .NET BACKEND (pythonnet) =========================
class DotNetBackend:
    def __init__(self, dll_path: str):
        import clr  # type: ignore
        import System  # type: ignore
        from System import String
        from System.Reflection import Assembly

        self.System = System
        self.String = String

        debug("Attempting .NET load via pythonnet…")
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"DLL not found: {dll_path}")

        # Load assembly directly with Reflection to also keep a handle
        self.asm = Assembly.LoadFrom(dll_path)
        self.types = list(self.asm.GetTypes())
        debug(f"Loaded .NET assembly: {self.asm.FullName}")
        debug(f"Types found: {len(self.types)}")

        # Inspect public methods for heuristics
        self._connect = None
        self._login = None
        self._departments = None
        self._device_info = None
        self._disconnect = None
        self._instance = None

        self._auto_wire()

    # --- Helper: find method by name candidates and parameter count shapes ---
    def _find_method(self, t, names: List[str]) -> Optional[Tuple[Any, bool]]:
        # Returns (method_info, is_static)
        for m in t.GetMethods():
            if any(m.Name.lower() == n.lower() for n in names):
                return (m, m.IsStatic)
        return None

    def _auto_wire(self):
        # Strategy:
        # pick the first type that exposes our target methods (instance or static)
        chosen_type = None
        methods: Dict[str, Tuple[Any, bool]] = {}

        for t in self.types:
            # Skip compiler-generated & resources
            if t.FullName is None:
                continue
            name = t.FullName
            if any(k in name for k in ["<", ">", "Resources", "Properties"]):
                continue

            cand = {}
            for key, lst in (
                ("connect", CANDIDATES_CONNECT),
                ("login", CANDIDATES_LOGIN),
                ("departments", CANDIDATES_DEPARTMENTS),
                ("device_info", CANDIDATES_DEVICE_INFO),
                ("disconnect", CANDIDATES_DISCONNECT),
            ):
                fm = self._find_method(t, lst)
                if fm:
                    cand[key] = fm

            if {"connect", "login", "departments", "device_info"}.issubset(cand.keys()):
                chosen_type = t
                methods = cand  # type: ignore
                break

        debug(f"Chosen .NET type: {getattr(chosen_type, 'FullName', None)}")
        if not chosen_type:
            # Print a compact catalog to help the user adjust names
            debug("Could not auto-wire methods. Available public methods (Type :: Method):")
            for t in self.types:
                try:
                    for m in t.GetMethods():
                        print(f"  {t.FullName} :: {m.Name}({', '.join(p.ParameterType.Name for p in m.GetParameters())})")
                except Exception:
                    pass
            raise RuntimeError("Could not auto-detect suitable methods; adjust CANDIDATES_* lists above.")

        # If instance methods, create an instance (use default constructor if any)
        if any(not is_static for _, is_static in methods.values()):
            try:
                self._instance = chosen_type()  # default ctor
            except Exception:
                # Try to find a parameterless constructor via Activator
                from System import Activator
                self._instance = Activator.CreateInstance(chosen_type)

        self._connect, _ = methods.get("connect")
        self._login, _ = methods.get("login")
        self._departments, _ = methods.get("departments")
        self._device_info, _ = methods.get("device_info")
        self._disconnect = methods.get("disconnect", (None, True))[0]

        debug("Auto-wired .NET methods:")
        debug(f"  connect    -> {self._connect}")
        debug(f"  login      -> {self._login}")
        debug(f"  departments-> {self._departments}")
        debug(f"  deviceInfo -> {self._device_info}")
        debug(f"  disconnect -> {self._disconnect}")

    # --- Invokers with permissive parameter shapes -------------------
    def _invoke(self, mi, *args):
        if self._instance is not None:
            return mi.Invoke(self._instance, args)
        return mi.Invoke(None, args)  # static

    def connect(self, host: str, port: int) -> None:
        # Accepts (string,int) or (string,int,int timeout)
        params = self._connect.GetParameters()
        if len(params) == 2:
            self._invoke(self._connect, host, port)
        elif len(params) >= 3:
            self._invoke(self._connect, host, port, 10000)
        else:
            raise RuntimeError("Unsupported Connect signature")

    def login(self, fiscal_password: str, cashier_id: int, pin: str) -> None:
        # Try common orders:
        # (cashier:int, pin:string, password:string)
        # (password:string, cashier:int, pin:string)
        # (department:int, cashier:int, pin:string, password:string)
        params = self._login.GetParameters()
        names = [p.Name.lower() for p in params]
        values: List[Any] = [None] * len(params)

        # heuristic map
        for i, p in enumerate(params):
            n = p.Name.lower()
            t = str(p.ParameterType.Name).lower()
            if "cashier" in n or (t in ("int32", "int") and values[i] is None and CASHIER_ID is not None):
                values[i] = int(cashier_id)
            elif "pin" in n:
                values[i] = str(pin)
            elif "pass" in n or "pwd" in n or "password" in n:
                values[i] = str(fiscal_password)
            elif "dept" in n:
                values[i] = int(DEPARTMENT)

        # fill remaining by a likely ordering fallback
        for i, v in enumerate(values):
            if v is None:
                # prefer adding password once if missing
                if any("pass" in nm for nm in names) and fiscal_password and not any(isinstance(x, str) and x == fiscal_password for x in values):
                    values[i] = fiscal_password
                elif any("cashier" in nm for nm in names) and not any(isinstance(x, int) and x == cashier_id for x in values):
                    values[i] = int(cashier_id)
                elif any("pin" in nm for nm in names) and not any(isinstance(x, str) and x == pin for x in values):
                    values[i] = pin
                elif any("dept" in nm for nm in names):
                    values[i] = int(DEPARTMENT)
                else:
                    values[i] = pin  # last resort filler

        self._invoke(self._login, *values)

    def get_departments(self) -> Any:
        result = self._invoke(self._departments)
        return self._maybe_json(result)

    def get_device_info(self) -> Any:
        result = self._invoke(self._device_info)
        return self._maybe_json(result)

    def disconnect(self) -> None:
        if self._disconnect is not None:
            try:
                self._invoke(self._disconnect)
            except Exception:
                pass

    @staticmethod
    def _maybe_json(obj: Any) -> Any:
        if obj is None:
            return None
        s = str(obj)
        s = s.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                return json.loads(s)
            except Exception:
                return s
        return s


# ================== NATIVE BACKEND (ctypes) ==========================
class ExportsInspector:
    """Optional PE export table reader (uses pefile if available)."""
    def __init__(self, dll_path: str):
        self.dll_path = dll_path
        self.names: List[str] = []
        try:
            import pefile  # type: ignore
            pe = pefile.PE(dll_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.name:
                        try:
                            self.names.append(sym.name.decode('utf-8', 'ignore'))
                        except Exception:
                            pass
        except Exception:
            # pefile not installed or failed to parse -> silently ignore
            self.names = []

    def find_like(self, bases: List[str]) -> Optional[str]:
        if not self.names:
            return None
        low = [b.lower() for b in bases]
        # Prefer exact case-insensitive matches first
        for n in self.names:
            if any(n.lower() == b for b in low):
                return n
        # Then contains matches
        for n in self.names:
            if any(b in n.lower() for b in low):
                return n
        # Try with common prefixes/suffixes
        for n in self.names:
            nn = n.lower()
            for base in low:
                for pref in NATIVE_NAME_PREFIXES:
                    for suff in NATIVE_SUFFIXES:
                        candidate = f"{pref}{base}{suff}".lower()
                        if candidate == nn or candidate in nn:
                            return n
        return None


class NativeBackend:
    def __init__(self, dll_path: str):
        debug("Attempting native DLL load via ctypes…")
        if platform.system() != "Windows":
            raise OSError("Native Windows DLLs require Windows.")
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"DLL not found: {dll_path}")
        try:
            self.lib = ctypes.WinDLL(dll_path)
        except Exception:
            self.lib = ctypes.CDLL(dll_path)
        self._handle = self.lib._handle
        self._exports = ExportsInspector(dll_path)
        if self._exports.names:
            debug(f"Exported functions found: {len(self._exports.names)}")
            # Print a small sample to help debugging
            for name in sorted(self._exports.names)[:30]:
                debug(f"  export: {name}")
        else:
            debug("Could not enumerate exports (install 'pefile' for better auto-detection).")

    def _get_proc(self, name: str) -> Optional[ctypes._CFuncPtr]:
        try:
            return getattr(self.lib, name)
        except AttributeError:
            return None

    def _resolve(self, base_names: List[str]) -> Tuple[Callable, bool]:
        """Resolve a function. Returns (callable, is_wide). Tries many patterns and export scan."""
        last_err = None
        # 1) Try direct prefix/suffix combos first
        for base in base_names:
            for pref in NATIVE_NAME_PREFIXES:
                for suff in NATIVE_SUFFIXES:
                    name = f"{pref}{base}{suff}"
                    fn = self._get_proc(name)
                    if fn:
                        wide = suff == "W"
                        debug(f"Resolved '{base}' -> {name} (wide={wide})")
                        return fn, wide
        # 2) Scan export table for something similar
        if self._exports.names:
            match = self._exports.find_like(base_names)
            if match:
                fn = self._get_proc(match)
                if fn:
                    wide = match.endswith('W')
                    debug(f"Resolved by exports: '{base_names}' -> {match} (wide={wide})")
                    return fn, wide
        # 3) Try stdcall-decorated variants like _FunctionName@N
        for base in base_names:
            for n in (8, 12, 16, 20, 24, 28, 32):
                decorated = f"_{base}@{n}"
                fn = self._get_proc(decorated)
                if fn:
                    debug(f"Resolved stdcall-decorated '{base}' -> {decorated}")
                    return fn, False
        raise AttributeError(f"Function not found for candidates: {base_names}")

    def connect(self, host: str, port: int, timeout_ms: int = 10000) -> None:
        fn, wide = self._resolve(CANDIDATES_CONNECT)
        # We try several common signatures conservatively.
        fn.restype = ctypes.c_int
        if wide:
            try:
                fn.argtypes = [ctypes.c_wchar_p, ctypes.c_uint16, ctypes.c_int]
                rc = fn(host, port, timeout_ms)
            except Exception:
                fn.argtypes = [ctypes.c_wchar_p, ctypes.c_uint16]
                rc = fn(host, port)
        else:
            try:
                fn.argtypes = [ctypes.c_char_p, ctypes.c_uint16, ctypes.c_int]
                rc = fn(host.encode('utf-8'), port, timeout_ms)
            except Exception:
                fn.argtypes = [ctypes.c_char_p, ctypes.c_uint16]
                rc = fn(host.encode('utf-8'), port)
        # Some APIs return 0 on success; some return positive handle. Treat negative as error.
        if isinstance(rc, int) and rc < 0:
            raise RuntimeError(f"Connect failed, rc={rc}")

    def login(self, fiscal_password: str, cashier_id: int, pin: str, department: int = DEPARTMENT) -> None:
        fn, wide = self._resolve(CANDIDATES_LOGIN)
        str_t = ctypes.c_wchar_p if wide else ctypes.c_char_p
        # Try several known shapes in order
        trials = [
            ([ctypes.c_int, str_t, str_t], (cashier_id, pin, fiscal_password)),
            ([str_t, ctypes.c_int, str_t], (fiscal_password, cashier_id, pin)),
            ([ctypes.c_int, ctypes.c_int, str_t, str_t], (department, cashier_id, pin, fiscal_password)),
        ]
        last_rc = None
        for argtypes, args in trials:
            try:
                fn.restype = ctypes.c_int
                fn.argtypes = argtypes
                call_args = []
                for a, t in zip(args, argtypes):
                    if t == str_t:
                        call_args.append(a if wide else a.encode('utf-8'))
                    else:
                        call_args.append(a)
                rc = fn(*call_args)
                last_rc = rc
                if not isinstance(rc, int) or rc >= 0:
                    return
            except Exception:
                continue
        raise RuntimeError(f"Login failed, rc={last_rc}")

    def get_departments(self) -> Any:
        fn, wide = self._resolve(CANDIDATES_DEPARTMENTS)
        out_len = 64 * 1024
        buf = ctypes.create_unicode_buffer(out_len) if wide else ctypes.create_string_buffer(out_len)
        fn.restype = ctypes.c_int
        try:
            fn.argtypes = [ctypes.c_void_p, ctypes.c_int]
            rc = fn(buf, out_len)
        except Exception:
            # Some APIs: returns pointer to string; no args
            fn.argtypes = []
            fn.restype = ctypes.c_wchar_p if wide else ctypes.c_char_p
            s = fn()
            if s is None:
                return None
            return _maybe_json(s if wide else s.decode('utf-8', 'ignore'))
        if rc < 0:
            raise RuntimeError(f"GetDepartments failed, rc={rc}")
        raw = buf.value if wide else buf.value.decode('utf-8', 'ignore')
        return _maybe_json(raw)

    def get_device_info(self) -> Any:
        fn, wide = self._resolve(CANDIDATES_DEVICE_INFO)
        out_len = 64 * 1024
        buf = ctypes.create_unicode_buffer(out_len) if wide else ctypes.create_string_buffer(out_len)
        fn.restype = ctypes.c_int
        try:
            fn.argtypes = [ctypes.c_void_p, ctypes.c_int]
            rc = fn(buf, out_len)
        except Exception:
            fn.argtypes = []
            fn.restype = ctypes.c_wchar_p if wide else ctypes.c_char_p
            s = fn()
            if s is None:
                return None
            return _maybe_json(s if wide else s.decode('utf-8', 'ignore'))
        if rc < 0:
            raise RuntimeError(f"GetDeviceInfo failed, rc={rc}")
        raw = buf.value if wide else buf.value.decode('utf-8', 'ignore')
        return _maybe_json(raw)

    def disconnect(self) -> None:
        try:
            fn, _ = self._resolve(CANDIDATES_DISCONNECT)
        except Exception:
            return
        try:
            fn()
        except Exception:
            pass

def _maybe_json(s: str) -> Any:
    s = (s or "").strip()
    if not s:
        return s
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            return json.loads(s)
        except Exception:
            return s
    return s


# ================== RUNNER ===========================================

def main():
    backend = None

    # Try .NET first
    try:
        import clr  # noqa: F401
        backend = DotNetBackend(DLL_PATH)
        debug("Using .NET backend.")
    except Exception as e_net:
        debug(f".NET path unavailable: {e_net}")
        # Try native next
        try:
            backend = NativeBackend(DLL_PATH)
            debug("Using native backend.")
        except Exception as e_native:
            debug(f"Native path unavailable: {e_native}")
            print("\n*** Could not load HDMPrint.dll as .NET or native.***\n"
                  "- Ensure the DLL is next to this script OR update DLL_PATH.\n"
                  "- If it's a .NET assembly, install pythonnet (pip install pythonnet).\n"
                  "- If it's native, run on Windows.")
            sys.exit(2)

    # Do the flow
    try:
        debug(f"Connecting to {HOST}:{PORT}…")
        backend.connect(HOST, PORT)
        debug("Connected.")

        debug("Logging in…")
        backend.login(FISCAL_PASSWORD, CASHIER_ID, CASHIER_PIN)
        debug("Login OK.")

        debug("Fetching departments…")
        deps = backend.get_departments()
        print("\n=== Departments ===")
        print(pretty(deps))

        debug("Fetching device info…")
        info = backend.get_device_info()
        print("\n=== Device Info ===")
        print(pretty(info))

    finally:
        try:
            backend.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    main()
