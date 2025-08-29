# run.py
from hdm_service import HDMClient, HDMError

# --------- YOUR CONNECTION / AUTH ---------
HDM_IP = "123.123.123.14"        # set to your HDM IP
HDM_PORT = 8123                  # set to your HDM Port
HDM_PASSWORD = "krLGfzRh"        # fiscal registration password

CASHIER_ID = 3
CASHIER_PIN = "4321"

def main():
    client = HDMClient(
        HDM_IP, HDM_PORT, HDM_PASSWORD,
        debug=True,
        timeout=30.0,
        proto_version=0x00,   # many devices want 0x00; fallback will try 0x05 automatically
        use_tls=False,        # start plaintext; fallback will try TLS automatically
        tls_verify=False      # set True if device presents a valid cert
    )

    # 1) First-key call (no session): operators + departments
    try:
        listing = client.get_operators_and_departments()
        print("Operators:", listing.get("c"))
        print("Departments:", listing.get("d"))
    except HDMError as e:
        print("Failed to fetch operators/departments:", e)

    # 2) Login → session key
    try:
        key = client.login(CASHIER_ID, CASHIER_PIN)
        print("Login OK; session key (24 bytes) established.")
    except HDMError as e:
        print("Login failed:", e)

    # 3) Example: get device time (session)
    try:
        dt = client.get_device_time()
        print("Device time:", dt)
    except HDMError as e:
        print("Get time failed:", e)

if __name__ == "__main__":
    main()
