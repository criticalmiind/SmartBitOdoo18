# hdm_fr_departments_fixed.py
# Requires: pip install comtypes
# Files:    hdm/HDMPrint.tlb (and HDMPrint.dll registered)

import os, json, sys

HOST = "123.123.123.14"
PORT = 8123
FISCAL_PASSWORD = "krLGfzRh"
OPERATOR_ID = 3
OPERATOR_PIN = "4321"

BASE = os.path.dirname(__file__)
TLB_PATH = os.path.join(BASE, "hdm", "HDMPrint.tlb")
FR_CLSID = "{C0D2BCF7-4877-4645-BD08-3F0D88E7C712}"  # from your TLB output

def p(*a): print("[HDM]", *a)

def maybe_json(s):
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
    return s

def main():
    if os.name != "nt":
        raise SystemExit("Windows-only (COM).")

    # Load type library (generates comtypes.gen module)
    from comtypes.client import GetModule, CreateObject
    if not os.path.exists(TLB_PATH):
        raise FileNotFoundError(f"Type library not found at {TLB_PATH}")
    GetModule(TLB_PATH)

    # Create FR instance
    fr = CreateObject(FR_CLSID)

    # --- Set connection/auth properties (use what the TLB exposed) ---
    # Mandatory:
    setattr(fr, "IP", HOST)
    setattr(fr, "Port", int(PORT))
    setattr(fr, "FRPassword", FISCAL_PASSWORD)

    # Optional but harmless (driver may ignore if not needed for this call):
    try: setattr(fr, "OperatorID", int(OPERATOR_ID))
    except Exception: pass
    try: setattr(fr, "OperatorPassword", str(OPERATOR_PIN))
    except Exception: pass

    # Reasonable timeouts/buffers if available:
    for prop, val in [
        ("ConnectionReadTimeout", 10000),
        ("ConnectionWriteTimeout", 10000),
        ("ConnectionSendBufferSize", 32768),
        ("ConnectionReceiveBufferSize", 32768),
    ]:
        try: setattr(fr, prop, val)
        except Exception: pass

    # --- Ping device (NO ARGS) ---
    if hasattr(fr, "ConnectionCheck"):
        p("Calling ConnectionCheck() …")
        try:
            rc = fr.ConnectionCheck()  # no arguments
            p("ConnectionCheck result:", rc)
        except Exception as e:
            p("ConnectionCheck warning:", e)

    # --- Fetch operators & departments (NO ARGS) ---
    if not hasattr(fr, "GetOperators"):
        raise SystemExit("FR.GetOperators not found on COM object.")

    p("Calling GetOperators() …")
    result = None
    try:
        result = fr.GetOperators()  # most drivers take no args and return JSON or fill props
    except TypeError as e:
        # Some builds expose it as a Sub/void; ignore return value then.
        p("GetOperators returned no value (void/sub). Proceeding. Msg:", e)

    # Try to parse any direct return
    parsed = maybe_json(result)

    # Also read properties the driver exposes
    deps_prop = None
    ops_prop = None
    try: deps_prop = maybe_json(getattr(fr, "FRDepartments"))
    except Exception: pass
    try: ops_prop  = maybe_json(getattr(fr, "FROperators"))
    except Exception: pass

    # Prefer explicit departments property; else look in returned JSON
    departments = None
    if isinstance(deps_prop, (list, dict, str)) and deps_prop:
        departments = deps_prop
    elif isinstance(parsed, dict):
        departments = parsed.get("d") or parsed.get("departments") or parsed.get("Departments")
    elif isinstance(parsed, list):
        # Some drivers return a list directly
        departments = parsed

    # Print everything we’ve got so you can see the payload
    print("\n=== Raw FROperators property ===")
    print(json.dumps(ops_prop, ensure_ascii=False, indent=2) if isinstance(ops_prop, (dict, list))
          else (ops_prop if ops_prop is not None else "(none)"))

    print("\n=== Raw FRDepartments property ===")
    print(json.dumps(deps_prop, ensure_ascii=False, indent=2) if isinstance(deps_prop, (dict, list))
          else (deps_prop if deps_prop is not None else "(none)"))

    if isinstance(parsed, (dict, list)):
        print("\n=== Raw GetOperators() return ===")
        print(json.dumps(parsed, ensure_ascii=False, indent=2))
    elif parsed is not None:
        print("\n=== Raw GetOperators() return ===")
        print(parsed)

    # Friendly summary
    if isinstance(departments, list):
        print("\n=== Departments (parsed) ===")
        for d in departments:
            did = (d.get("id") or d.get("ID")) if isinstance(d, dict) else None
            name = (d.get("name") or d.get("Name")) if isinstance(d, dict) else str(d)
            dtype = (d.get("type") or d.get("Type")) if isinstance(d, dict) else None
            print(f"ID={did}  Name={name}  Type={dtype}")
    else:
        print("\n(No structured departments list detected; see raw sections above.)")

if __name__ == "__main__":
    main()
