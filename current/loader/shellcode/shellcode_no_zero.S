.global _start
.section .text
_start: 
	// syscall(write:4, fd=1, buf="hello world!", 13)
	xor %ebx, %ebx
	inc %ebx	// ebx = 1
	lea 3(%ebx), %eax
	lea 5(%ebx), %edx
	jmp msg
next:
	pop %ecx
	int $0x80
	xor %eax, %eax
	inc %al
	int $0x80
msg:
	call next
.asciz "hello\n"
