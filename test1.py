# hdm_departments_com.py
# Minimal COM-based caller for HDMPrint.tlb/HDMPrint.dll to fetch Departments

import os, sys, json, re
from typing import Any, List, Tuple, Optional

HOST = "123.123.123.14"
PORT = 8123
FISCAL_PASSWORD = "krLGfzRh"
CASHIER_ID = 3
CASHIER_PIN = "4321"
DEPARTMENT = 1

BASE_DIR = os.path.dirname(__file__)
TLB_PATH = os.path.join(BASE_DIR, "hdm", "HDMPrint.tlb")
DLL_PATH = os.path.join(BASE_DIR, "hdm", "HDMPrint.dll")  # optional (registration)

# Candidate names we try to match on the COM object (case-insensitive)
CANDIDATES_CONNECT = ["ConnectTCP", "Connect", "OpenTCP", "Open", "Init", "Initialize", "Start", "InitializeDevice"]
CANDIDATES_LOGIN   = ["LoginEx", "Login", "CashierLogin", "OperatorLogin", "Authorize", "Auth"]
CANDIDATES_DEPS    = ["GetDepartmentsJSON", "GetDepartmentList", "GetDepartments", "Departments"]

PREFIXES = ["", "HDM_", "Hdm_", "FR_", "Fr_"]

def debug(msg: str): print(f"[HDM] {msg}")

def pretty(obj: Any) -> str:
    try: return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception: return str(obj)

def load_type_library() -> Any:
    from comtypes.client import GetModule
    if not os.path.exists(TLB_PATH):
        raise FileNotFoundError(f"Type library not found: {TLB_PATH}")
    mod = GetModule(TLB_PATH)  # generates comtypes.gen.<something>
    debug(f"Loaded TLB: {TLB_PATH}")
    return mod

def iter_coclasses(mod) -> List[Tuple[str, str]]:
    """
    Return [(name, clsid_str), ...] for all CoClasses in the type library.
    """
    import comtypes.gen
    py_mod = sys.modules[mod.__name__]  # generated python module
    result = []
    for name in dir(py_mod):
        obj = getattr(py_mod, name)
        if hasattr(obj, "_reg_clsid_"):
            try:
                clsid = obj._reg_clsid_
                result.append((name, str(clsid)))
            except Exception:
                pass
    return result

def create_com_object(clsid: str):
    from comtypes.client import CreateObject
    # Use CLSID directly; avoids needing ProgID
    return CreateObject(clsid)

def list_methods(obj) -> List[str]:
    # comtypes IDispatch exposes methods as attributes; filter dunders/props
    names = []
    for n in dir(obj):
        if n.startswith("_"):
            continue
        try:
            attr = getattr(obj, n)
            if callable(attr):
                names.append(n)
        except Exception:
            continue
    return sorted(names, key=str.lower)

def resolve_method(obj, candidates: List[str]) -> Optional[str]:
    methods = list_methods(obj)
    low = [m.lower() for m in methods]
    # exact matches (with common prefixes)
    for base in candidates:
        for pref in PREFIXES:
            want = (pref + base).lower()
            if want in low:
                return methods[low.index(want)]
    # contains matches
    for base in candidates:
        for i, m in enumerate(low):
            if base.lower() in m:
                return methods[i]
    return None

def try_call(fn, argsets: List[tuple]):
    last = None
    for args in argsets:
        try:
            return fn(*args)
        except Exception as e:
            last = e
            continue
    raise RuntimeError(f"Call failed for all signatures. Last={last}")

def main():
    # 1) Load type library and find coclasses
    mod = load_type_library()
    coclasses = iter_coclasses(mod)
    if not coclasses:
        raise SystemExit("No CoClasses found in TLB. Is the TLB correct?")

    debug(f"Found {len(coclasses)} CoClass(es): " + ", ".join(f"{n}={c}" for n, c in coclasses))
    last_err = None

    for name, clsid in coclasses:
        debug(f"Trying CoClass {name} ({clsid}) …")
        try:
            obj = create_com_object(clsid)
        except Exception as e:
            last_err = e
            debug(f"  CreateObject failed: {e}")
            continue

        methods = list_methods(obj)
        debug(f"  Methods: {', '.join(methods) or '(none)'}")

        # 2) Resolve connect/init
        m_connect = resolve_method(obj, CANDIDATES_CONNECT)
        if not m_connect:
            debug("  No connect/initialize-like method. Trying next CoClass …")
            continue
        debug(f"  Using connect method: {m_connect}")

        # 3) Resolve login (optional)
        m_login = resolve_method(obj, CANDIDATES_LOGIN)
        if m_login:
            debug(f"  Using login method: {m_login}")
        else:
            debug("  No login-like method found (may not be required).")

        # 4) Resolve departments
        m_deps = resolve_method(obj, CANDIDATES_DEPS)
        if not m_deps:
            debug("  No departments-like method found. Trying next CoClass …")
            continue
        debug(f"  Using departments method: {m_deps}")

        # 5) Connect
        try:
            fn = getattr(obj, m_connect)
            # common signatures: (host, port, timeout) or (host, port)
            try_call(fn, [
                (HOST, int(PORT), 10000),
                (HOST, int(PORT)),
            ])
            debug("  Connected.")
        except Exception as e:
            last_err = e
            debug(f"  Connect failed: {e}")
            continue

        # 6) Login (optional)
        if m_login:
            try:
                fn = getattr(obj, m_login)
                # try common orders:
                try_call(fn, [
                    (int(CASHIER_ID), str(CASHIER_PIN), str(FISCAL_PASSWORD)),
                    (str(FISCAL_PASSWORD), int(CASHIER_ID), str(CASHIER_PIN)),
                    (int(DEPARTMENT), int(CASHIER_ID), str(CASHIER_PIN), str(FISCAL_PASSWORD)),
                ])
                debug("  Login OK.")
            except Exception as e:
                debug(f"  Login failed (continuing anyway): {e}")

        # 7) Get Departments
        try:
            fn = getattr(obj, m_deps)
            # Most COM drivers return a JSON/text string and take no args
            try:
                res = fn()
            except TypeError:
                # Rare buffer form (discouraged in COM) – try (outLen) or (None)
                res = fn(65536)
            if isinstance(res, (bytes, bytearray)):
                res = res.decode("utf-8", "ignore")
            # pretty print
            print("\n=== Departments (raw) ===")
            try:
                print(pretty(json.loads(res)))
            except Exception:
                print(res)
            return
        except Exception as e:
            last_err = e
            debug(f"  GetDepartments failed: {e}")
            continue

    # If we reached here, none of the CoClasses worked end-to-end
    raise SystemExit(f"Could not fetch departments via COM. Last error: {last_err}")

if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit("This COM approach requires Windows.")
    main()
