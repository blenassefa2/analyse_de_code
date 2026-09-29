.global _start
.section .text
_start: 
	// syscall(write:4, fd=1, buf="hello world!", 13)
	mov $4, %eax
	mov $1, %ebx
	jmp msg
next:
	pop %ecx
	mov $6, %edx
	int $0x80
	// syscall(exit:1)
	mov $1, %eax
	int $0x80
msg:
	call next
.asciz "hello\n"
