import socket

HDM_IP = "123.123.123.14"
HDM_PORT = 8123

# Raw test frame (just the 12-byte header, body length=0)
# Header layout: MAGIC(7) + proto(1) + func(1) + bodyLen(2) + reserved(1)
frame = bytes.fromhex("D580D4B4D58400")  # MAGIC
frame += b"\x05"       # protocol version
frame += b"\x01"       # function code (Get operators & deps)
frame += (0).to_bytes(2, "big")  # body length = 0
frame += b"\x00"       # reserved

print("Sending test frame:", frame.hex().upper())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(5)
    s.connect((HDM_IP, HDM_PORT))
    s.sendall(frame)

    try:
        resp = s.recv(1024)
        print("Received:", resp.hex().upper())
    except socket.timeout:
        print("No response (timeout).")
