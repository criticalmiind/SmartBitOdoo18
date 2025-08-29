# run.py
from hdm_service import HDMClient, HDMError

HDM_IP = "123.123.123.14"
HDM_PORT = 8123
HDM_PASSWORD = "krLGfzRh"

CASHIER_ID = 3
CASHIER_PIN = "4321"

def main():
    client = HDMClient(HDM_IP, HDM_PORT, HDM_PASSWORD, timeout=30.0, debug=True)

    # 1) Operators & Departments (first-key)
    try:
        listing = client.get_operators_and_departments()
        print("Operators:", listing.get("c"))
        print("Departments:", listing.get("d"))
    except HDMError as e:
        print("Failed to fetch operators/departments:", e)

    # 2) Login (session)
    try:
        client.login(CASHIER_ID, CASHIER_PIN)
        print("Login OK; session key established.")
    except HDMError as e:
        print("Login failed:", e)
        return

    # 3) Example session call
    try:
        dt = client.get_device_time()
        print("Device time:", dt)
    except HDMError as e:
        print("Get time failed:", e)

if __name__ == "__main__":
    main()
