# Requires: pip install comtypes
# Place next to: hdm/HDMPrint.tlb (+ HDMPrint.dll registered or loadable)

import os, sys, json
from typing import Any, List, Tuple

HOST = "123.123.123.14"
PORT = 8123
FISCAL_PASSWORD = "krLGfzRh"
CASHIER_ID = 3
CASHIER_PIN = "4321"
DEPARTMENT = 1

BASE = os.path.dirname(__file__)
TLB_PATH = os.path.join(BASE, "hdm", "HDMPrint.tlb")

FR_CLSID = "{C0D2BCF7-4877-4645-BD08-3F0D88E7C712}"  # from your log

def debug(*a): print("[HDM]", *a)

def load_tlb():
    from comtypes.client import GetModule
    if not os.path.exists(TLB_PATH):
        raise FileNotFoundError(f"Type library not found at {TLB_PATH}")
    return GetModule(TLB_PATH)

def create_fr():
    from comtypes.client import CreateObject
    return CreateObject(FR_CLSID)  # instantiate FR CoClass

def list_members(obj):
    methods, props = [], []
    for name in dir(obj):
        if name.startswith("_"): 
            continue
        try:
            attr = getattr(obj, name)
            (methods if callable(attr) else props).append(name)
        except Exception:
            continue
    return sorted(methods, key=str.lower), sorted(props, key=str.lower)

def set_if_exists(obj, name, value):
    if hasattr(obj, name):
        try:
            setattr(obj, name, value)
            debug(f"set {name} = {value!r}")
        except Exception as e:
            debug(f"couldn't set {name}: {e}")

def try_call(fn, argsets: List[tuple]):
    last = None
    for args in argsets:
        try:
            return fn(*args)
        except Exception as e:
            last = e
            continue
    raise RuntimeError(f"{fn.__name__} failed for all tried signatures. Last={last}")

def maybe_json(s: Any):
    if s is None: 
        return None
    if isinstance(s, (bytes, bytearray)):
        s = s.decode("utf-8", "ignore")
    if isinstance(s, str):
        t = s.strip()
        if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
            try: 
                return json.loads(t)
            except Exception:
                return s
    return s

def main():
    if os.name != "nt":
        raise SystemExit("Windows only (COM).")

    load_tlb()
    fr = create_fr()

    methods, props = list_members(fr)
    debug("FR methods:", ", ".join(methods) or "(none)")
    debug("FR props  :", ", ".join(props) or "(none)")

    # Many drivers expose connection fields as properties
    for cand, val in [
        ("Host", HOST), ("IP", HOST), ("Address", HOST), ("Server", HOST),
        ("Port", int(PORT)), ("Password", FISCAL_PASSWORD), ("Pass", FISCAL_PASSWORD),
        ("Cashier", int(CASHIER_ID)), ("Operator", int(CASHIER_ID)),
        ("Pin", str(CASHIER_PIN)), ("PIN", str(CASHIER_PIN)),
        ("Department", int(DEPARTMENT)), ("Dept", int(DEPARTMENT))
    ]:
        set_if_exists(fr, cand, val)

    # 1) Connectivity check if available
    if hasattr(fr, "ConnectionCheck"):
        debug("Calling ConnectionCheck …")
        rc = try_call(fr.ConnectionCheck, [
            (HOST, int(PORT), FISCAL_PASSWORD),   # common
            (HOST, int(PORT)),                    # sometimes no password
        ])
        debug("ConnectionCheck result:", rc)

    # 2) Fetch operators+departments (vendors often return both here)
    if not hasattr(fr, "GetOperators"):
        raise SystemExit("FR.GetOperators not found on COM object — cannot proceed.")

    debug("Calling GetOperators …")
    res = try_call(fr.GetOperators, [
        (FISCAL_PASSWORD,),                                  # spec-like: password only
        (HOST, int(PORT), FISCAL_PASSWORD),                  # some drivers require host/port
        (FISCAL_PASSWORD, int(CASHIER_ID), str(CASHIER_PIN)) # if auth baked in
    ])
    data = maybe_json(res)

    print("\n=== Raw GetOperators result ===")
    if isinstance(data, (dict, list)):
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(res)

    # 3) Try to extract departments commonly under keys: "d", "departments"
    deps = None
    if isinstance(data, dict):
        deps = data.get("d") or data.get("departments") or data.get("Departments")
    if deps:
        print("\n=== Departments ===")
        for d in deps:
            did = d.get("id") or d.get("ID")
            name = d.get("name") or d.get("Name")
            dtype = d.get("type") or d.get("Type")
            print(f"ID={did}  Name={name}  Type={dtype}")

if __name__ == "__main__":
    main()
