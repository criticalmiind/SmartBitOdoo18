# hdm_fr_departments_fixed.py
# Requires: pip install comtypes
# Files:    hdm/HDMPrint.tlb (and HDMPrint.dll registered)

import os, json, sys

HOST = "123.123.123.14"
PORT = 8123
FR_PASSWORD = "krlGfzRh"   # <-- from your 1C screenshot (lowercase `l`)
OPERATOR_ID = 3
OPERATOR_PIN = "4321"

BASE = os.path.dirname(__file__)
TLB_PATH = os.path.join(BASE, "hdm", "HDMPrint.tlb")
FR_CLSID = "{C0D2BCF7-4877-4645-BD08-3F0D88E7C712}"  # FR CoClass

def p(*a): print("[HDM]", *a)

def maybe_json(val):
    if val is None: return None
    if isinstance(val, (bytes, bytearray)):
        val = val.decode("utf-8", "ignore")
    if isinstance(val, str):
        t = val.strip()
        if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
            try: return json.loads(t)
            except Exception: return val
        return val
    return val

def dump_err(fr, prefix=""):
    errc = getattr(fr, "ErrCode", None)
    errd = getattr(fr, "ErrDescription", None)
    p(f"{prefix}ErrCode={errc} ErrDescription={errd}")

def iter_com_collection(coll):
    """Handles (), lists, SAFEARRAYs and collections of COM Department/Operator objects."""
    if coll is None: return
    # comtypes often shows SAFEARRAY as tuple
    if isinstance(coll, tuple):
        items = list(coll)
    elif isinstance(coll, list):
        items = coll
    else:
        # Try to enumerate COM collection if it supports it
        try:
            it = iter(coll)
            items = list(it)
        except Exception:
            items = [coll]
    for it in items:
        yield it

def read_dep_obj(obj):
    # Try common property names; ignore missing ones
    for k in ("ID", "Id", "id"):
        try:
            did = getattr(obj, k)
            break
        except Exception:
            did = None
    for k in ("Name", "name"):
        try:
            name = getattr(obj, k)
            break
        except Exception:
            name = None
    for k in ("Type", "type"):
        try:
            dtyp = getattr(obj, k)
            break
        except Exception:
            dtyp = None
    return did, name, dtyp

def main():
    if os.name != "nt":
        raise SystemExit("Windows-only (COM).")

    from comtypes.client import GetModule, CreateObject
    if not os.path.exists(TLB_PATH):
        raise FileNotFoundError(f"Type library not found at {TLB_PATH}")
    GetModule(TLB_PATH)

    fr = CreateObject(FR_CLSID)

    # Set connection/auth properties (from your TLB dump)
    fr.IP = HOST
    fr.Port = int(PORT)
    fr.FRPassword = FR_PASSWORD
    try: fr.OperatorID = int(OPERATOR_ID)
    except Exception: pass
    try: fr.OperatorPassword = str(OPERATOR_PIN)
    except Exception: pass
    # Optional quality-of-life props if available
    for prop, val in [
        ("ConnectionReadTimeout", 10000),
        ("ConnectionWriteTimeout", 10000),
        ("ConnectionSendBufferSize", 32768),
        ("ConnectionReceiveBufferSize", 32768),
        ("ArmenianEncoding", True),
    ]:
        try: setattr(fr, prop, val)
        except Exception: pass

    # 1) Ping
    if hasattr(fr, "ConnectionCheck"):
        p("Calling ConnectionCheck() …")
        try:
            ok = fr.ConnectionCheck()   # no args
            p("ConnectionCheck:", ok)
        except Exception as e:
            p("ConnectionCheck exception:", e)
        dump_err(fr, "ConnectionCheck: ")

    # 2) Operators & Departments
    if not hasattr(fr, "GetOperators"):
        raise SystemExit("FR.GetOperators not found.")

    p("Calling GetOperators() …")
    ret = None
    try:
        ret = fr.GetOperators()  # most builds: no args
    except TypeError:
        # some builds expose as Sub (void)
        pass
    dump_err(fr, "GetOperators: ")

    parsed = maybe_json(ret)

    # Read properties filled by the driver
    try: fr_ops = getattr(fr, "FROperators")
    except Exception: fr_ops = None
    try: fr_deps = getattr(fr, "FRDepartments")
    except Exception: fr_deps = None

    # Print raw payloads
    print("\n=== Raw FROperators property ===")
    if isinstance(fr_ops, (dict, list)):
        print(json.dumps(fr_ops, ensure_ascii=False, indent=2))
    else:
        print(fr_ops if fr_ops is not None else "(none)")

    print("\n=== Raw FRDepartments property ===")
    if isinstance(fr_deps, (dict, list)):
        print(json.dumps(fr_deps, ensure_ascii=False, indent=2))
    else:
        print(fr_deps if fr_deps is not None else "(none)")

    if parsed is not None:
        print("\n=== Raw GetOperators() return ===")
        print(parsed if not isinstance(parsed, (dict, list))
              else json.dumps(parsed, ensure_ascii=False, indent=2))

    # Try to iterate COM collections and print nicely
    printed_any = False
    if fr_deps:
        print("\n=== Departments (from FRDepartments) ===")
        for item in iter_com_collection(fr_deps):
            did, name, dtyp = read_dep_obj(item)
            print(f"ID={did}  Name={name}  Type={dtyp}")
            printed_any = True

    if not printed_any and isinstance(parsed, dict):
        deps = parsed.get("d") or parsed.get("departments") or parsed.get("Departments")
        if deps:
            print("\n=== Departments (from JSON) ===")
            for d in deps:
                did = d.get("id") or d.get("ID")
                name = d.get("name") or d.get("Name")
                dtyp = d.get("type") or d.get("Type")
                print(f"ID={did}  Name={name}  Type={dtyp}")
            printed_any = True

    if not printed_any:
        print("\n(No structured departments detected; see raw sections and ErrCode/ErrDescription.)")

if __name__ == "__main__":
    main()
