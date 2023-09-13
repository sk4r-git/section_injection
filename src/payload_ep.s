BITS 64

SECTION .text
global main

main:
  ; save context
  push rbp
  push rsp
  push rax 
  push rcx
  push rdx
  push rsi
  push rdi
  push r11
  push rbx

  ; fill here later
  mov r9, 0x0a656e696d726574
  push r9
  mov r9, 0x206c696176617254
  push r9
  mov rdx, 24
  mov rsi, rsp
  mov rdi, 1  
  mov rax, 1 
  syscall 
  
  ; load context
  pop rbx
  pop rbx
  pop rbx
  pop r11
  pop rdi
  pop rsi
  pop rdx
  pop rcx
  pop rax
  pop rsp
  pop rbp
  
  pop r10       ; = 2 bytes
  jmp r10 ; = 3 bytes
  ; return
  ret ; = 1 byte

  ;ancien ep = 0x4022e0 => 0xc02e50
  ;notre ep =  0x800b70 => 
