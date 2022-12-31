; Demo Assembly Program
; This program demonstrates various assembly instructions
; and can be loaded into Opasm

; Initialize some registers with values
mov rax, 0x1234
mov rbx, 0x1111
mov rcx, 0x2222

; Perform some arithmetic operations
add rax, rbx
sub rcx, rbx
imul rbx, rbx, 2

; Stack operations
push rax
push rbx
push rcx

; Pop values in reverse order
pop rdx
pop rsi
pop rdi

; Logical operations
and rax, 0xff
or rbx, 0xf000
xor rcx, rcx

; Memory operations using register values
mov qword ptr [rsp], rax
mov qword ptr [rsp+8], rbx

; Some interesting bit manipulation
shl rax, 4
shr rbx, 2

; Final operations
inc rax
dec rbx
neg rcx

; Load some more interesting values
mov r8, 0xcafebabe
mov r9, 0xdeadbeef
add r8, r9

; Clear a register
xor r10, r10
inc r10
dec r10

; End marker instruction
nop
