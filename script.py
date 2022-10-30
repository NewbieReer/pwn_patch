from keystone import *
#function_addr = 0xdeadbeef
target_addr = 0x403208  # eh_frame
back_addr = 0x40260B  # jump back
hijack_flow = 0x402604  # jump out

jmp_to = 'jmp ' + hex(target_addr)
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(jmp_to, hijack_flow)
jmp_to_byte = b''
for i in encoding:
    jmp_to_byte += bytes([i])

jmp_to_byte_len = len(jmp_to_byte)
print("jmp_to_byte_len is " + str(jmp_to_byte_len))
print("Append broken byte?")

for i in range(0, jmp_to_byte_len):
    ida_bytes.patch_word(hijack_flow + i, jmp_to_byte[i])

bak_from_broken = 'mov rax, [rbp-0x28];'+'mov rsi,rax;'
encoding, count = ks.asm(bak_from_broken)
bak_from_broken_byte = b''
for i in encoding:
    bak_from_broken_byte += bytes([i])
print(bak_from_broken_byte)

#  write your asm code in code_str
'''
bak_reg_code = 'push '  # or xchg
call_code = 'call ' + hex(function_addr) + ';'
mov_reg_code = ''
recover_code = 'pop '
code_str = bak_reg_code + call_code + mov_reg_code + recover_code
'''

code_str = 'cmp edx, 0x10; jle _l1; mov edx, 0x10; _l1: jmp ' + \
    hex(back_addr) + ';'
CODE = b''
encoding, count = ks.asm(code_str,
                         target_addr + len(bak_from_broken_byte))
for i in encoding:
    CODE += bytes([i])


jmp_back = 'jmp ' + hex(back_addr)
encoding, count = ks.asm(jmp_back, target_addr +
                         len(bak_from_broken_byte) + len(CODE))
jmp_to_byte = b''
for i in encoding:
    jmp_to_byte += bytes([i])

main_patch = bak_from_broken_byte + CODE + jmp_to_byte

length = len(main_patch)
for i in range(0, length):
    ida_bytes.patch_word(target_addr + i, main_patch[i])
