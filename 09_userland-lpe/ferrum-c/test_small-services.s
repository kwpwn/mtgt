	.file	"services.c"
	.text
	.section .rdata,"dr"
	.align 8
.LC0:
	.ascii "S\0E\0R\0V\0I\0C\0E\0 \0M\0I\0S\0C\0O\0N\0F\0I\0G\0U\0R\0A\0T\0I\0O\0N\0\0\0"
	.align 8
.LC1:
	.ascii " \0 \0[\0!\0]\0 \0C\0a\0n\0n\0o\0t\0 \0o\0p\0e\0n\0 \0S\0C\0M\0 \0(\0e\0r\0r\0o\0r\0 \0%\0l\0u\0)\0\12\0\0\0"
	.align 2
.LC2:
	.ascii "S\0E\0R\0V\0I\0C\0E\0S\0\0\0"
	.align 8
.LC3:
	.ascii "U\0n\0q\0u\0o\0t\0e\0d\0 \0s\0e\0r\0v\0i\0c\0e\0 \0p\0a\0t\0h\0 \0w\0i\0t\0h\0 \0s\0p\0a\0c\0e\0s\0:\0 \0%\0s\0\0\0"
	.align 8
.LC4:
	.ascii "S\0e\0r\0v\0i\0c\0e\0 \0b\0i\0n\0a\0r\0y\0 \0i\0n\0 \0u\0s\0e\0r\0-\0w\0r\0i\0t\0a\0b\0l\0e\0 \0l\0o\0c\0a\0t\0i\0o\0n\0:\0 \0%\0s\0\0\0"
	.align 8
.LC5:
	.ascii "S\0e\0r\0v\0i\0c\0e\0 \0b\0i\0n\0a\0r\0y\0 \0i\0s\0 \0W\0R\0I\0T\0A\0B\0L\0E\0 \0b\0y\0 \0c\0u\0r\0r\0e\0n\0t\0 \0u\0s\0e\0r\0:\0 \0%\0s\0\0\0"
	.align 8
.LC6:
	.ascii "S\0E\0R\0V\0I\0C\0E\0_\0C\0H\0A\0N\0G\0E\0_\0C\0O\0N\0F\0I\0G\0 \0g\0r\0a\0n\0t\0e\0d\0 \0t\0o\0 \0u\0n\0p\0r\0i\0v\0i\0l\0e\0g\0e\0d\0 \0S\0I\0D\0 \0(\0B\0U\0I\0L\0T\0I\0N\0\\\0U\0s\0e\0r\0s\0 \0/\0 \0E\0v\0e\0r\0y\0o\0n\0e\0)\0\0\0"
	.align 8
.LC7:
	.ascii "S\0Y\0S\0T\0E\0M\0\\\0C\0u\0r\0r\0e\0n\0t\0C\0o\0n\0t\0r\0o\0l\0S\0e\0t\0\\\0S\0e\0r\0v\0i\0c\0e\0s\0\\\0%\0s\0\\\0P\0a\0r\0a\0m\0e\0t\0e\0r\0s\0\0\0"
	.align 2
.LC8:
	.ascii "S\0e\0r\0v\0i\0c\0e\0D\0l\0l\0\0\0"
	.align 8
.LC9:
	.ascii "S\0e\0r\0v\0i\0c\0e\0D\0l\0l\0 \0i\0s\0 \0w\0r\0i\0t\0a\0b\0l\0e\0 \0o\0r\0 \0i\0n\0 \0u\0s\0e\0r\0-\0w\0r\0i\0t\0a\0b\0l\0e\0 \0p\0a\0t\0h\0:\0 \0%\0s\0\0\0"
	.align 8
.LC10:
	.ascii " \0 \0N\0o\0 \0s\0e\0r\0v\0i\0c\0e\0 \0m\0i\0s\0c\0o\0n\0f\0i\0g\0u\0r\0a\0t\0i\0o\0n\0s\0 \0f\0o\0u\0n\0d\0.\0\12\0\0\0"
	.align 8
.LC11:
	.ascii " \0 \0T\0o\0t\0a\0l\0 \0f\0i\0n\0d\0i\0n\0g\0s\0:\0 \0%\0l\0u\0\12\0\0\0"
	.text
	.p2align 4
	.globl	Module_Services
	.def	Module_Services;	.scl	2;	.type	32;	.endef
	.seh_proc	Module_Services
Module_Services:
	pushq	%r15
	.seh_pushreg	%r15
	movl	$4520, %eax
	pushq	%r14
	.seh_pushreg	%r14
	pushq	%r13
	.seh_pushreg	%r13
	pushq	%r12
	.seh_pushreg	%r12
	pushq	%rbp
	.seh_pushreg	%rbp
	pushq	%rdi
	.seh_pushreg	%rdi
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	call	___chkstk_ms
	subq	%rax, %rsp
	.seh_stackalloc	4520
	.seh_endprologue
	leaq	.LC0(%rip), %rcx
	call	PrintHeader
	movl	$5, %r8d
	xorl	%edx, %edx
	xorl	%ecx, %ecx
	call	*__imp_OpenSCManagerW(%rip)
	movq	%rax, 104(%rsp)
	testq	%rax, %rax
	je	.L115
	movq	104(%rsp), %r14
	xorl	%edx, %edx
	movl	$3, %r9d
	leaq	184(%rsp), %rbp
	leaq	180(%rsp), %rdi
	movq	%rbp, 64(%rsp)
	leaq	176(%rsp), %rsi
	movq	__imp_EnumServicesStatusExW(%rip), %rbx
	movl	$0, 176(%rsp)
	movl	$48, %r8d
	movq	%r14, %rcx
	movl	$0, 180(%rsp)
	movl	$0, 184(%rsp)
	movq	$0, 72(%rsp)
	movq	%rdi, 56(%rsp)
	movq	%rsi, 48(%rsp)
	movl	$0, 40(%rsp)
	movq	$0, 32(%rsp)
	call	*%rbx
	movq	__imp_GetLastError(%rip), %rax
	movq	%rax, 120(%rsp)
	call	*%rax
	cmpl	$234, %eax
	jne	.L116
	movl	176(%rsp), %r12d
	movq	__imp_GetProcessHeap(%rip), %r13
	call	*%r13
	xorl	%edx, %edx
	movq	%rax, %rcx
	movq	__imp_HeapAlloc(%rip), %rax
	movq	%r12, %r8
	movq	%rax, 112(%rsp)
	call	*%rax
	movq	%rax, %r12
	testq	%rax, %rax
	je	.L109
	movl	176(%rsp), %eax
	xorl	%edx, %edx
	movl	$0, 184(%rsp)
	movl	$3, %r9d
	movq	%rbp, 64(%rsp)
	movq	104(%rsp), %rcx
	movl	$48, %r8d
	movq	$0, 72(%rsp)
	movq	%rdi, 56(%rsp)
	movq	%rsi, 48(%rsp)
	movl	%eax, 40(%rsp)
	movq	%r12, 32(%rsp)
	call	*%rbx
	testl	%eax, %eax
	je	.L6
	movl	180(%rsp), %ebx
	testl	%ebx, %ebx
	je	.L117
	movq	%r12, 152(%rsp)
	movq	%r12, %r14
	xorl	%r15d, %r15d
	movl	$0, 132(%rsp)
	.p2align 4
	.p2align 3
.L51:
	movq	(%r14), %rbp
	movq	104(%rsp), %rcx
	movl	$131077, %r8d
	movq	%rbp, %rdx
	call	*__imp_OpenServiceW(%rip)
	movq	%rax, %rbx
	testq	%rax, %rax
	je	.L9
	leaq	188(%rsp), %r9
	xorl	%r8d, %r8d
	xorl	%edx, %edx
	movq	%rax, %rcx
	movl	$0, 188(%rsp)
	xorl	%edi, %edi
	call	*__imp_QueryServiceConfigW(%rip)
	movl	188(%rsp), %esi
	call	*%r13
	xorl	%edx, %edx
	movq	%rsi, %r8
	movq	%rax, %rcx
	call	*112(%rsp)
	movq	%rax, %rsi
	testq	%rax, %rax
	je	.L10
	movl	188(%rsp), %r8d
	leaq	188(%rsp), %r9
	movq	%rax, %rdx
	movq	%rbx, %rcx
	call	*__imp_QueryServiceConfigW(%rip)
	movl	%eax, %edi
	testl	%eax, %eax
	je	.L10
	movq	16(%rsi), %rax
	movl	$1, %edi
	movq	%rax, 136(%rsp)
	testq	%rax, %rax
	je	.L10
	leaq	1264(%rsp), %r12
	movl	$1040, %r8d
	xorl	%edx, %edx
	movq	%r12, %rcx
	call	memset
	movq	136(%rsp), %rcx
	movl	$520, %r8d
	movq	%r12, %rdx
	call	ExtractExePath
	leaq	2304(%rsp), %rax
	leaq	2308(%rsp), %rcx
	leaq	.LC2(%rip), %rdx
	movq	%rax, 144(%rsp)
	call	wcscpy
	movzwl	1264(%rsp), %eax
	testw	%ax, %ax
	je	.L13
	cmpw	$34, %ax
	jne	.L118
.L11:
	testw	%ax, %ax
	je	.L13
	movq	%r12, %rcx
	call	IsUserWritablePath
	testl	%eax, %eax
	jne	.L119
.L14:
	cmpw	$0, 1264(%rsp)
	je	.L13
	movq	%r12, %rcx
	call	*__imp_GetFileAttributesW(%rip)
	cmpl	$-1, %eax
	jne	.L120
	.p2align 4
	.p2align 3
.L13:
	movl	$1, %edi
	.p2align 4
	.p2align 3
.L10:
	xorl	%r9d, %r9d
	xorl	%r8d, %r8d
	movl	$4, %edx
	movq	%rbx, %rcx
	leaq	192(%rsp), %r12
	movl	$0, 192(%rsp)
	movq	%r12, 32(%rsp)
	call	*__imp_QueryServiceObjectSecurity(%rip)
	call	*120(%rsp)
	cmpl	$122, %eax
	je	.L121
.L39:
	testl	%edi, %edi
	je	.L40
	testb	$32, (%rsi)
	jne	.L122
.L49:
	call	*%r13
	movq	%rsi, %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
.L50:
	movq	%rbx, %rcx
	call	*__imp_CloseServiceHandle(%rip)
.L9:
	addl	$1, %r15d
	addq	$56, %r14
	cmpl	180(%rsp), %r15d
	jb	.L51
	movq	152(%rsp), %r12
	call	*%r13
	xorl	%edx, %edx
	movq	%r12, %r8
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
	movq	104(%rsp), %rcx
	call	*__imp_CloseServiceHandle(%rip)
	movl	132(%rsp), %eax
	testl	%eax, %eax
	je	.L53
	movl	132(%rsp), %edx
	leaq	.LC11(%rip), %rcx
	call	PrintInfo
	jmp	.L1
	.p2align 4,,10
	.p2align 3
.L116:
	movq	%r14, %rcx
	call	*__imp_CloseServiceHandle(%rip)
	nop
.L1:
	addq	$4520, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	ret
	.p2align 4,,10
	.p2align 3
.L40:
	testq	%rsi, %rsi
	jne	.L49
	jmp	.L50
	.p2align 4,,10
	.p2align 3
.L121:
	movl	192(%rsp), %r8d
	movq	%r8, 136(%rsp)
	call	*%r13
	movq	136(%rsp), %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*112(%rsp)
	movq	%rax, 136(%rsp)
	testq	%rax, %rax
	je	.L39
	movq	%r12, 32(%rsp)
	movq	%rax, %r8
	movq	%rax, %r12
	movl	$4, %edx
	movl	192(%rsp), %r9d
	movq	%rbx, %rcx
	call	*__imp_QueryServiceObjectSecurity(%rip)
	testl	%eax, %eax
	jne	.L20
	call	*%r13
	movq	%r12, %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
	jmp	.L39
	.p2align 4,,10
	.p2align 3
.L122:
	leaq	1264(%rsp), %r12
	xorl	%edx, %edx
	movl	$1040, %r8d
	movq	%r12, %rcx
	call	memset
	movq	%rbp, %r9
	leaq	.LC7(%rip), %r8
	movl	$512, %edx
	leaq	240(%rsp), %rcx
	call	*__imp__snwprintf(%rip)
	leaq	232(%rsp), %rax
	xorl	%r8d, %r8d
	movq	$0, 232(%rsp)
	movq	%rax, 32(%rsp)
	movl	$131097, %r9d
	leaq	240(%rsp), %rdx
	movq	$-2147483646, %rcx
	call	*__imp_RegOpenKeyExW(%rip)
	testl	%eax, %eax
	jne	.L49
	leaq	224(%rsp), %rax
	xorl	%r8d, %r8d
	movq	232(%rsp), %rcx
	movl	$0, 216(%rsp)
	movq	%rax, 40(%rsp)
	leaq	216(%rsp), %r9
	leaq	.LC8(%rip), %rdx
	movl	$1040, 224(%rsp)
	movq	%r12, 32(%rsp)
	call	*__imp_RegQueryValueExW(%rip)
	movq	232(%rsp), %rcx
	movl	%eax, %edi
	call	*__imp_RegCloseKey(%rip)
	testl	%edi, %edi
	jne	.L49
	leaq	2304(%rsp), %rdi
	movl	$520, %r8d
	movq	%r12, %rcx
	movq	%rdi, %rdx
	movq	%rdi, 144(%rsp)
	call	*__imp_ExpandEnvironmentStringsW(%rip)
	movq	%rdi, %rdx
	movl	$519, %r8d
	movq	%r12, %rcx
	call	wcsncpy
	xorl	%edx, %edx
	movw	%dx, 2302(%rsp)
	cmpw	$0, 1264(%rsp)
	je	.L49
	movq	%r12, %rcx
	call	IsUserWritablePath
	testl	%eax, %eax
	jne	.L47
	movq	%r12, %rcx
	call	IsFileWritable
	testl	%eax, %eax
	je	.L49
.L47:
	leaq	.LC2(%rip), %rdx
	leaq	2308(%rsp), %rcx
	call	wcscpy
	movq	%r12, %rcx
	call	IsFileWritable
	leaq	2436(%rsp), %rcx
	movl	$519, %r8d
	movq	%rbp, %rdx
	cmpl	$1, %eax
	movl	$3, %eax
	sbbl	$-1, %eax
	movl	%eax, 2304(%rsp)
	call	wcsncpy
	leaq	3476(%rsp), %rcx
	movq	%r12, %r9
	leaq	.LC9(%rip), %r8
	movl	$512, %edx
	call	*__imp__snwprintf(%rip)
	movq	144(%rsp), %rcx
	call	PrintFinding
	addl	$1, 132(%rsp)
	jmp	.L49
	.p2align 4,,10
	.p2align 3
.L20:
	movq	136(%rsp), %rcx
	leaq	196(%rsp), %rdx
	movl	$0, 196(%rsp)
	leaq	200(%rsp), %r9
	movl	$0, 200(%rsp)
	leaq	216(%rsp), %r8
	movq	$0, 216(%rsp)
	call	*__imp_GetSecurityDescriptorDacl(%rip)
	testl	%eax, %eax
	je	.L108
	movl	196(%rsp), %r11d
	testl	%r11d, %r11d
	je	.L108
	cmpq	$0, 216(%rsp)
	je	.L108
	movl	$1280, %r8d
	movl	$256, %r9d
	leaq	224(%rsp), %rax
	movq	__imp_AllocateAndInitializeSid(%rip), %r12
	movw	%r8w, 208(%rsp)
	movl	$2, %edx
	movl	$32, %r8d
	leaq	204(%rsp), %rcx
	movw	%r9w, 214(%rsp)
	movl	$545, %r9d
	movq	$0, 224(%rsp)
	movq	$0, 232(%rsp)
	movq	$0, 240(%rsp)
	movl	$0, 204(%rsp)
	movl	$0, 210(%rsp)
	movq	%rax, 80(%rsp)
	movl	$0, 72(%rsp)
	movl	$0, 64(%rsp)
	movl	$0, 56(%rsp)
	movl	$0, 48(%rsp)
	movl	$0, 40(%rsp)
	movl	$0, 32(%rsp)
	call	*%r12
	xorl	%r9d, %r9d
	xorl	%r8d, %r8d
	movl	$1, %edx
	leaq	232(%rsp), %rax
	leaq	210(%rsp), %rcx
	movl	$0, 72(%rsp)
	movq	%rax, 80(%rsp)
	movl	$0, 64(%rsp)
	movl	$0, 56(%rsp)
	movl	$0, 48(%rsp)
	movl	$0, 40(%rsp)
	movl	$0, 32(%rsp)
	call	*%r12
	leaq	240(%rsp), %rax
	xorl	%r9d, %r9d
	movl	$1, %edx
	movl	$11, %r8d
	leaq	204(%rsp), %rcx
	movq	%rax, 80(%rsp)
	movl	$0, 72(%rsp)
	movl	$0, 64(%rsp)
	movl	$0, 56(%rsp)
	movl	$0, 48(%rsp)
	movl	$0, 40(%rsp)
	movl	$0, 32(%rsp)
	call	*%r12
	movl	$2, %r9d
	movl	$12, %r8d
	leaq	2304(%rsp), %rax
	movq	$0, 2304(%rsp)
	movq	216(%rsp), %rcx
	movq	%rax, %rdx
	movl	$0, 2312(%rsp)
	movq	%rax, 144(%rsp)
	call	*__imp_GetAclInformation(%rip)
	movl	2304(%rsp), %r10d
	testl	%r10d, %r10d
	je	.L24
	movq	%rbx, 168(%rsp)
	xorl	%ebx, %ebx
	.p2align 4
	.p2align 3
.L34:
	movq	$0, 1264(%rsp)
	movq	216(%rsp), %rcx
	leaq	1264(%rsp), %r8
	movl	%ebx, %edx
	call	*__imp_GetAce(%rip)
	testl	%eax, %eax
	je	.L113
	movq	1264(%rsp), %rax
	cmpb	$0, (%rax)
	jne	.L111
	movq	224(%rsp), %rdx
	leaq	8(%rax), %rcx
	testq	%rdx, %rdx
	je	.L29
	movq	%rcx, 160(%rsp)
	call	*__imp_EqualSid(%rip)
	movq	160(%rsp), %rcx
	testl	%eax, %eax
	jne	.L30
.L29:
	movq	232(%rsp), %rdx
	testq	%rdx, %rdx
	je	.L31
	movq	%rcx, 160(%rsp)
	call	*__imp_EqualSid(%rip)
	movq	160(%rsp), %rcx
	testl	%eax, %eax
	jne	.L30
.L31:
	movq	240(%rsp), %rdx
	testq	%rdx, %rdx
	je	.L111
	call	*__imp_EqualSid(%rip)
	testl	%eax, %eax
	je	.L113
.L30:
	movq	1264(%rsp), %rax
	addl	$1, %ebx
	movl	4(%rax), %r9d
	andl	$2, %r9d
	cmpl	2304(%rsp), %ebx
	jnb	.L123
	testl	%r9d, %r9d
	je	.L34
	movq	168(%rsp), %rbx
	movl	$1, %r9d
.L27:
	movq	224(%rsp), %rcx
	testq	%rcx, %rcx
	je	.L35
	movl	%r9d, 160(%rsp)
	call	*__imp_FreeSid(%rip)
	movl	160(%rsp), %r9d
.L35:
	movq	232(%rsp), %rcx
	testq	%rcx, %rcx
	je	.L36
	movl	%r9d, 160(%rsp)
	call	*__imp_FreeSid(%rip)
	movl	160(%rsp), %r9d
.L36:
	movq	240(%rsp), %rcx
	testq	%rcx, %rcx
	je	.L37
	movl	%r9d, 160(%rsp)
	call	*__imp_FreeSid(%rip)
	movl	160(%rsp), %r9d
.L37:
	movl	%r9d, 160(%rsp)
	call	*%r13
	movq	136(%rsp), %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
	movl	160(%rsp), %ecx
	testl	%ecx, %ecx
	je	.L39
	leaq	2308(%rsp), %rcx
	leaq	.LC2(%rip), %rdx
	call	wcscpy
	movl	$519, %r8d
	leaq	2436(%rsp), %rcx
	movq	%rbp, %rdx
	movl	$4, 2304(%rsp)
	call	wcsncpy
	leaq	3476(%rsp), %rcx
	leaq	.LC6(%rip), %rdx
	call	wcscpy
	movq	144(%rsp), %rcx
	call	PrintFinding
	addl	$1, 132(%rsp)
	jmp	.L39
	.p2align 4,,10
	.p2align 3
.L117:
	call	*%r13
	movq	%r12, %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
	movq	104(%rsp), %rcx
	call	*__imp_CloseServiceHandle(%rip)
.L53:
	leaq	.LC10(%rip), %rcx
	call	PrintInfo
	jmp	.L1
	.p2align 4,,10
	.p2align 3
.L115:
	call	*__imp_GetLastError(%rip)
	leaq	.LC1(%rip), %rcx
	movl	%eax, %edx
	addq	$4520, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	jmp	PrintInfo
	.p2align 4,,10
	.p2align 3
.L6:
	call	*%r13
	movq	%r12, %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
.L109:
	movq	104(%rsp), %rcx
	call	*__imp_CloseServiceHandle(%rip)
	jmp	.L1
	.p2align 4,,10
	.p2align 3
.L108:
	call	*%r13
	movq	136(%rsp), %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
	jmp	.L39
	.p2align 4,,10
	.p2align 3
.L118:
	movl	$32, %edx
	movq	%r12, %rcx
	call	wcschr
	testq	%rax, %rax
	jne	.L12
.L105:
	movzwl	1264(%rsp), %eax
	jmp	.L11
	.p2align 4,,10
	.p2align 3
.L120:
	movq	%r12, %rcx
	call	IsFileWritable
	testl	%eax, %eax
	je	.L13
	leaq	2436(%rsp), %rcx
	movq	%rbp, %rdx
	movl	$519, %r8d
	movl	$4, 2304(%rsp)
	call	wcsncpy
	leaq	3476(%rsp), %rcx
	movq	%r12, %r9
	leaq	.LC5(%rip), %r8
	movl	$512, %edx
	call	*__imp__snwprintf(%rip)
	movq	144(%rsp), %rcx
	call	PrintFinding
	addl	$1, 132(%rsp)
	jmp	.L13
	.p2align 4,,10
	.p2align 3
.L119:
	leaq	2436(%rsp), %rcx
	movq	%rbp, %rdx
	movl	$519, %r8d
	movl	$3, 2304(%rsp)
	call	wcsncpy
	leaq	3476(%rsp), %rcx
	movq	%r12, %r9
	leaq	.LC4(%rip), %r8
	movl	$512, %edx
	call	*__imp__snwprintf(%rip)
	movq	144(%rsp), %rcx
	call	PrintFinding
	addl	$1, 132(%rsp)
	jmp	.L14
	.p2align 4,,10
	.p2align 3
.L12:
	leaq	2436(%rsp), %rcx
	movq	%rbp, %rdx
	movl	$519, %r8d
	movl	$3, 2304(%rsp)
	call	wcsncpy
	movq	136(%rsp), %r9
	movl	$512, %edx
	leaq	3476(%rsp), %rcx
	leaq	.LC3(%rip), %r8
	call	*__imp__snwprintf(%rip)
	movq	144(%rsp), %rcx
	call	PrintFinding
	addl	$1, 132(%rsp)
	jmp	.L105
	.p2align 4,,10
	.p2align 3
.L111:
	addl	$1, %ebx
	cmpl	2304(%rsp), %ebx
	jb	.L34
	movq	168(%rsp), %rbx
.L24:
	xorl	%r9d, %r9d
	jmp	.L27
	.p2align 4,,10
	.p2align 3
.L113:
	addl	$1, %ebx
	cmpl	2304(%rsp), %ebx
	jb	.L34
	movq	168(%rsp), %rbx
	movl	%eax, %r9d
	jmp	.L27
.L123:
	movq	168(%rsp), %rbx
	shrl	%r9d
	jmp	.L27
	.seh_endproc
	.ident	"GCC: (Rev2, Built by MSYS2 project) 16.1.0"
	.def	PrintHeader;	.scl	2;	.type	32;	.endef
	.def	memset;	.scl	2;	.type	32;	.endef
	.def	ExtractExePath;	.scl	2;	.type	32;	.endef
	.def	wcscpy;	.scl	2;	.type	32;	.endef
	.def	IsUserWritablePath;	.scl	2;	.type	32;	.endef
	.def	PrintInfo;	.scl	2;	.type	32;	.endef
	.def	wcsncpy;	.scl	2;	.type	32;	.endef
	.def	IsFileWritable;	.scl	2;	.type	32;	.endef
	.def	PrintFinding;	.scl	2;	.type	32;	.endef
	.def	wcschr;	.scl	2;	.type	32;	.endef
