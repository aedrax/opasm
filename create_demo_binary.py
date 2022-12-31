#!/usr/bin/env python3
"""
Create a demo binary blob for the Assembly REPL
This generates machine code that can be loaded as a binary file
"""

# Simple x64 machine code instructions
machine_code = [
    # mov rax, 0x4142434445464748  (loads "ABCDEFGH" as hex)
    0x48, 0xb8, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41,
    
    # mov rbx, 0x1000
    0x48, 0xc7, 0xc3, 0x00, 0x10, 0x00, 0x00,
    
    # add rax, rbx
    0x48, 0x01, 0xd8,
    
    # push rax
    0x50,
    
    # mov rcx, 0x200
    0x48, 0xc7, 0xc1, 0x00, 0x02, 0x00, 0x00,
    
    # sub rax, rcx
    0x48, 0x29, 0xc8,
    
    # pop rdx
    0x5a,
    
    # xor rsi, rsi (clear rsi)
    0x48, 0x31, 0xf6,
    
    # inc rsi
    0x48, 0xff, 0xc6,
    
    # dec rsi
    0x48, 0xff, 0xce,
    
    # nop (padding)
    0x90, 0x90, 0x90, 0x90,
]

# Write binary file
with open('demo.bin', 'wb') as f:
    f.write(bytes(machine_code))

print("Created demo.bin with machine code")
print(f"Size: {len(machine_code)} bytes")
print("Instructions included:")
print("  mov rax, 0x4142434445464748  ; Load 'ABCDEFGH'")
print("  mov rbx, 0x1000             ; Load 0x1000")
print("  add rax, rbx                ; Add them")
print("  push rax                    ; Push result")
print("  mov rcx, 0x200              ; Load 0x200")
print("  sub rax, rcx                ; Subtract")
print("  pop rdx                     ; Pop to rdx")
print("  xor rsi, rsi                ; Clear rsi")
print("  inc rsi                     ; Increment rsi")
print("  dec rsi                     ; Decrement rsi")
print("  nop                         ; Padding")
