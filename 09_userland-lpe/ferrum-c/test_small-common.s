	.file	"common.c"
	.text
	.p2align 4
	.def	AccessCheckForObject;	.scl	3;	.type	32;	.endef
	.seh_proc	AccessCheckForObject
AccessCheckForObject:
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$144, %rsp
	.seh_stackalloc	144
	.seh_endprologue
	xorl	%ebx, %ebx
	leaq	80(%rsp), %rax
	movl	%r8d, 176(%rsp)
	movl	$7, %r8d
	movq	%rax, 56(%rsp)
	leaq	88(%rsp), %rax
	movq	%r9, 184(%rsp)
	xorl	%r9d, %r9d
	movq	$0, 80(%rsp)
	movq	$0, 88(%rsp)
	movq	$0, 96(%rsp)
	movq	$0, 104(%rsp)
	movq	$0, 48(%rsp)
	movq	%rax, 40(%rsp)
	movq	$0, 32(%rsp)
	call	*__imp_GetNamedSecurityInfoW(%rip)
	testl	%eax, %eax
	je	.L23
.L2:
	movq	80(%rsp), %rcx
	testq	%rcx, %rcx
	je	.L3
	call	*__imp_LocalFree(%rip)
.L3:
	movq	96(%rsp), %rcx
	testq	%rcx, %rcx
	je	.L4
	call	*__imp_CloseHandle(%rip)
.L4:
	movq	104(%rsp), %rcx
	testq	%rcx, %rcx
	je	.L1
	call	*__imp_CloseHandle(%rip)
.L1:
	movl	%ebx, %eax
	addq	$144, %rsp
	popq	%rbx
	ret
	.p2align 4,,10
	.p2align 3
.L23:
	call	*__imp_GetCurrentProcess(%rip)
	leaq	96(%rsp), %r8
	movl	$10, %edx
	movq	%rax, %rcx
	call	*__imp_OpenProcessToken(%rip)
	movl	%eax, %ebx
	testl	%eax, %eax
	je	.L2
	movq	96(%rsp), %rcx
	leaq	104(%rsp), %r8
	movl	$2, %edx
	call	*__imp_DuplicateToken(%rip)
	movl	%eax, %ebx
	testl	%eax, %eax
	je	.L2
	movq	184(%rsp), %rdx
	leaq	176(%rsp), %rcx
	call	*__imp_MapGenericMask(%rip)
	leaq	76(%rsp), %rax
	movl	$20, 68(%rsp)
	movq	184(%rsp), %r9
	movq	%rax, 56(%rsp)
	leaq	72(%rsp), %rax
	movl	176(%rsp), %r8d
	movq	104(%rsp), %rdx
	movq	80(%rsp), %rcx
	movq	%rax, 48(%rsp)
	leaq	68(%rsp), %rax
	movq	%rax, 40(%rsp)
	leaq	112(%rsp), %rax
	movl	$0, 72(%rsp)
	movl	$0, 76(%rsp)
	movq	%rax, 32(%rsp)
	call	*__imp_AccessCheck(%rip)
	movl	76(%rsp), %ebx
	jmp	.L2
	.seh_endproc
	.section .rdata,"dr"
	.align 8
.LC0:
	.ascii "\12\0\33\0[\0"
	.ascii "1\0m\0\33\0[\0"
	.ascii "9\0"
	.ascii "6\0m\0[\0*\0]\0 \0=\0=\0=\0 \0%\0s\0 \0=\0=\0=\0\33\0[\0"
	.ascii "0\0m\0\12\0\0\0"
	.align 8
.LC1:
	.ascii "\12\0[\0*\0]\0 \0=\0=\0=\0 \0%\0s\0 \0=\0=\0=\0\12\0\0\0"
	.text
	.p2align 4
	.globl	PrintHeader
	.def	PrintHeader;	.scl	2;	.type	32;	.endef
	.seh_proc	PrintHeader
PrintHeader:
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$32, %rsp
	.seh_stackalloc	32
	.seh_endprologue
	movl	g_noColor(%rip), %eax
	movq	%rcx, %rbx
	movq	%rcx, %rdx
	testl	%eax, %eax
	jne	.L25
	leaq	.LC0(%rip), %rcx
	call	wprintf
	movq	g_outFile(%rip), %rcx
	testq	%rcx, %rcx
	je	.L24
.L28:
	movq	%rbx, %r8
	leaq	.LC1(%rip), %rdx
	addq	$32, %rsp
	popq	%rbx
	jmp	fwprintf
	.p2align 4,,10
	.p2align 3
.L25:
	leaq	.LC1(%rip), %rcx
	call	wprintf
	movq	g_outFile(%rip), %rcx
	testq	%rcx, %rcx
	jne	.L28
.L24:
	addq	$32, %rsp
	popq	%rbx
	ret
	.seh_endproc
	.section .rdata,"dr"
	.align 2
.LC2:
	.ascii "\0\0"
	.align 2
.LC3:
	.ascii "I\0N\0F\0O\0\0\0"
	.align 2
.LC4:
	.ascii "?\0?\0?\0\0\0"
	.align 2
.LC5:
	.ascii "\33\0[\0"
	.ascii "0\0m\0\0\0"
	.align 2
.LC6:
	.ascii "\33\0[\0"
	.ascii "9\0"
	.ascii "1\0m\0\0\0"
	.align 2
.LC7:
	.ascii "H\0I\0G\0H\0\0\0"
	.align 2
.LC8:
	.ascii "C\0R\0I\0T\0I\0C\0A\0L\0\0\0"
	.align 2
.LC9:
	.ascii "L\0O\0W\0\0\0"
	.align 2
.LC10:
	.ascii "\33\0[\0"
	.ascii "9\0"
	.ascii "3\0m\0\0\0"
	.align 2
.LC11:
	.ascii "M\0E\0D\0I\0U\0M\0\0\0"
	.align 2
.LC12:
	.ascii "\33\0[\0"
	.ascii "9\0"
	.ascii "5\0m\0\0\0"
	.align 2
.LC13:
	.ascii "\33\0[\0"
	.ascii "9\0"
	.ascii "6\0m\0\0\0"
	.align 2
.LC14:
	.ascii "\33\0[\0"
	.ascii "9\0"
	.ascii "2\0m\0\0\0"
	.align 8
.LC15:
	.ascii " \0 \0%\0s\0[\0%\0s\0]\0%\0s\0 \0[\0%\0s\0]\0 \0%\0s\0\12\0 \0 \0 \0 \0 \0 \0 \0 \0-\0>\0 \0%\0s\0\12\0\0\0"
	.align 8
.LC16:
	.ascii " \0 \0[\0%\0s\0]\0 \0[\0%\0s\0]\0 \0%\0s\0\12\0 \0 \0 \0 \0 \0 \0 \0 \0-\0>\0 \0%\0s\0\12\0\0\0"
	.text
	.p2align 4
	.globl	PrintFinding
	.def	PrintFinding;	.scl	2;	.type	32;	.endef
	.seh_proc	PrintFinding
PrintFinding:
	pushq	%rbp
	.seh_pushreg	%rbp
	pushq	%rdi
	.seh_pushreg	%rdi
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$72, %rsp
	.seh_stackalloc	72
	.seh_endprologue
	movl	g_noColor(%rip), %edx
	movl	(%rcx), %eax
	testl	%edx, %edx
	jne	.L30
	cmpl	$4, %eax
	ja	.L31
	leaq	.L33(%rip), %rdx
	movslq	(%rdx,%rax,4), %rax
	addq	%rdx, %rax
	jmp	*%rax
	.section .rdata,"dr"
	.align 4
.L33:
	.long	.L37-.L33
	.long	.L36-.L33
	.long	.L45-.L33
	.long	.L34-.L33
	.long	.L32-.L33
	.text
	.p2align 4,,10
	.p2align 3
.L30:
	cmpl	$4, %eax
	ja	.L38
	leaq	.L40(%rip), %rdx
	movslq	(%rdx,%rax,4), %rax
	addq	%rdx, %rax
	leaq	.LC2(%rip), %rdx
	jmp	*%rax
	.section .rdata,"dr"
	.align 4
.L40:
	.long	.L43-.L40
	.long	.L42-.L40
	.long	.L46-.L40
	.long	.L41-.L40
	.long	.L39-.L40
	.text
	.p2align 4,,10
	.p2align 3
.L45:
	leaq	.LC10(%rip), %rdx
	leaq	.LC11(%rip), %rbp
	leaq	.LC5(%rip), %r9
	.p2align 4
	.p2align 3
.L35:
	leaq	1172(%rcx), %rdi
	leaq	132(%rcx), %rsi
	movq	%rbp, %r8
	leaq	4(%rcx), %rbx
	movq	%rdi, 48(%rsp)
	leaq	.LC15(%rip), %rcx
	movq	%rsi, 40(%rsp)
	movq	%rbx, 32(%rsp)
	call	wprintf
	movq	g_outFile(%rip), %rcx
	testq	%rcx, %rcx
	je	.L29
	movq	%rdi, 40(%rsp)
	movq	%rbx, %r9
	movq	%rbp, %r8
	leaq	.LC16(%rip), %rdx
	movq	%rsi, 32(%rsp)
	call	fwprintf
	nop
.L29:
	addq	$72, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	ret
	.p2align 4,,10
	.p2align 3
.L37:
	leaq	.LC14(%rip), %rdx
	leaq	.LC3(%rip), %rbp
	leaq	.LC5(%rip), %r9
	jmp	.L35
	.p2align 4,,10
	.p2align 3
.L36:
	leaq	.LC13(%rip), %rdx
	leaq	.LC9(%rip), %rbp
	leaq	.LC5(%rip), %r9
	jmp	.L35
	.p2align 4,,10
	.p2align 3
.L34:
	leaq	.LC6(%rip), %rdx
	leaq	.LC7(%rip), %rbp
	leaq	.LC5(%rip), %r9
	jmp	.L35
	.p2align 4,,10
	.p2align 3
.L32:
	leaq	.LC12(%rip), %rdx
	leaq	.LC8(%rip), %rbp
	leaq	.LC5(%rip), %r9
	jmp	.L35
	.p2align 4,,10
	.p2align 3
.L46:
	leaq	.LC11(%rip), %rbp
	movq	%rdx, %r9
	jmp	.L35
	.p2align 4,,10
	.p2align 3
.L43:
	leaq	.LC3(%rip), %rbp
	movq	%rdx, %r9
	jmp	.L35
	.p2align 4,,10
	.p2align 3
.L42:
	leaq	.LC9(%rip), %rbp
	movq	%rdx, %r9
	jmp	.L35
	.p2align 4,,10
	.p2align 3
.L41:
	leaq	.LC7(%rip), %rbp
	movq	%rdx, %r9
	jmp	.L35
	.p2align 4,,10
	.p2align 3
.L39:
	leaq	.LC8(%rip), %rbp
	movq	%rdx, %r9
	jmp	.L35
.L31:
	leaq	.LC2(%rip), %rdx
	leaq	.LC4(%rip), %rbp
	leaq	.LC5(%rip), %r9
	jmp	.L35
.L38:
	leaq	.LC2(%rip), %rdx
	leaq	.LC4(%rip), %rbp
	movq	%rdx, %r9
	jmp	.L35
	.seh_endproc
	.p2align 4
	.globl	PrintInfo
	.def	PrintInfo;	.scl	2;	.type	32;	.endef
	.seh_proc	PrintInfo
PrintInfo:
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$56, %rsp
	.seh_stackalloc	56
	.seh_endprologue
	leaq	88(%rsp), %rsi
	movq	%rdx, 88(%rsp)
	movq	%rcx, %rbx
	movq	%rsi, %rdx
	movq	%r8, 96(%rsp)
	movq	%r9, 104(%rsp)
	movq	%rsi, 40(%rsp)
	call	vwprintf
	cmpq	$0, g_outFile(%rip)
	je	.L50
	movq	g_outFile(%rip), %rcx
	movq	%rsi, %r8
	movq	%rbx, %rdx
	movq	%rsi, 40(%rsp)
	call	vfwprintf
	nop
.L50:
	addq	$56, %rsp
	popq	%rbx
	popq	%rsi
	ret
	.seh_endproc
	.p2align 4
	.globl	IsFileWritable
	.def	IsFileWritable;	.scl	2;	.type	32;	.endef
	.seh_proc	IsFileWritable
IsFileWritable:
	subq	$56, %rsp
	.seh_stackalloc	56
	.seh_endprologue
	movdqu	.LC17(%rip), %xmm0
	movl	$1073741824, %r8d
	movl	$1, %edx
	leaq	32(%rsp), %r9
	movups	%xmm0, 32(%rsp)
	call	AccessCheckForObject
	addq	$56, %rsp
	ret
	.seh_endproc
	.p2align 4
	.globl	IsDirWritable
	.def	IsDirWritable;	.scl	2;	.type	32;	.endef
	.seh_proc	IsDirWritable
IsDirWritable:
	subq	$56, %rsp
	.seh_stackalloc	56
	.seh_endprologue
	movdqu	.LC17(%rip), %xmm0
	movl	$1073741824, %r8d
	movl	$1, %edx
	leaq	32(%rsp), %r9
	movups	%xmm0, 32(%rsp)
	call	AccessCheckForObject
	addq	$56, %rsp
	ret
	.seh_endproc
	.section .rdata,"dr"
	.align 2
.LC18:
	.ascii "M\0A\0C\0H\0I\0N\0E\0\0\0"
	.align 2
.LC19:
	.ascii "C\0U\0R\0R\0E\0N\0T\0_\0U\0S\0E\0R\0\0\0"
	.align 2
.LC20:
	.ascii "U\0S\0E\0R\0S\0\0\0"
	.align 2
.LC21:
	.ascii "U\0N\0K\0N\0O\0W\0N\0\0\0"
	.align 2
.LC22:
	.ascii "C\0L\0A\0S\0S\0E\0S\0_\0R\0O\0O\0T\0\0\0"
	.align 2
.LC23:
	.ascii "%\0s\0\\\0%\0s\0\0\0"
	.text
	.p2align 4
	.globl	IsRegKeyWritable
	.def	IsRegKeyWritable;	.scl	2;	.type	32;	.endef
	.seh_proc	IsRegKeyWritable
IsRegKeyWritable:
	subq	$1096, %rsp
	.seh_stackalloc	1096
	.seh_endprologue
	leaq	.LC18(%rip), %r9
	cmpq	$-2147483646, %rcx
	je	.L55
	leaq	.LC19(%rip), %r9
	cmpq	$-2147483647, %rcx
	je	.L55
	leaq	.LC20(%rip), %r9
	cmpq	$-2147483645, %rcx
	je	.L55
	leaq	.LC22(%rip), %r9
	cmpq	$-2147483648, %rcx
	leaq	.LC21(%rip), %rax
	cmovne	%rax, %r9
.L55:
	movq	%rdx, 32(%rsp)
	leaq	64(%rsp), %rcx
	leaq	.LC23(%rip), %r8
	movl	$512, %edx
	call	*__imp__snwprintf(%rip)
	leaq	48(%rsp), %r9
	movl	$2, %r8d
	movdqu	.LC24(%rip), %xmm0
	movl	$4, %edx
	leaq	64(%rsp), %rcx
	movups	%xmm0, 48(%rsp)
	call	AccessCheckForObject
	addq	$1096, %rsp
	ret
	.seh_endproc
	.section .rdata,"dr"
	.align 2
.LC25:
	.ascii "\\\0u\0s\0e\0r\0s\0\\\0\0\0"
	.align 2
.LC26:
	.ascii "\\\0t\0e\0m\0p\0\\\0\0\0"
	.align 2
.LC27:
	.ascii "\\\0p\0r\0o\0g\0r\0a\0m\0d\0a\0t\0a\0\\\0\0\0"
	.align 2
.LC28:
	.ascii "\\\0a\0p\0p\0d\0a\0t\0a\0\\\0\0\0"
	.align 2
.LC29:
	.ascii "\\\0t\0m\0p\0\\\0\0\0"
	.text
	.p2align 4
	.globl	IsUserWritablePath
	.def	IsUserWritablePath;	.scl	2;	.type	32;	.endef
	.seh_proc	IsUserWritablePath
IsUserWritablePath:
	subq	$1080, %rsp
	.seh_stackalloc	1080
	.seh_endprologue
	movl	$519, %r8d
	movq	%rcx, %rdx
	leaq	32(%rsp), %rcx
	call	wcsncpy
	xorl	%eax, %eax
	leaq	32(%rsp), %rcx
	movw	%ax, 1070(%rsp)
	call	*__imp__wcslwr(%rip)
	leaq	.LC25(%rip), %rdx
	leaq	32(%rsp), %rcx
	call	wcsstr
	testq	%rax, %rax
	je	.L64
.L66:
	movl	$1, %eax
.L63:
	addq	$1080, %rsp
	ret
	.p2align 4,,10
	.p2align 3
.L64:
	leaq	.LC26(%rip), %rdx
	leaq	32(%rsp), %rcx
	call	wcsstr
	testq	%rax, %rax
	jne	.L66
	leaq	.LC27(%rip), %rdx
	leaq	32(%rsp), %rcx
	call	wcsstr
	testq	%rax, %rax
	jne	.L66
	leaq	.LC28(%rip), %rdx
	leaq	32(%rsp), %rcx
	call	wcsstr
	testq	%rax, %rax
	jne	.L66
	leaq	.LC29(%rip), %rdx
	leaq	32(%rsp), %rcx
	call	wcsstr
	testq	%rax, %rax
	setne	%al
	movzbl	%al, %eax
	jmp	.L63
	.seh_endproc
	.p2align 4
	.globl	GetProcessUser
	.def	GetProcessUser;	.scl	2;	.type	32;	.endef
	.seh_proc	GetProcessUser
GetProcessUser:
	pushq	%r14
	.seh_pushreg	%r14
	pushq	%rdi
	.seh_pushreg	%rdi
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$1144, %rsp
	.seh_stackalloc	1144
	.seh_endprologue
	xorl	%ebx, %ebx
	movq	%rdx, 1192(%rsp)
	xorl	%edx, %edx
	movl	%r8d, 1200(%rsp)
	movl	%ecx, %r8d
	movl	$4096, %ecx
	call	*__imp_OpenProcess(%rip)
	movq	%rax, %rsi
	testq	%rax, %rax
	je	.L67
	leaq	104(%rsp), %r8
	movl	$8, %edx
	movq	%rax, %rcx
	movq	$0, 104(%rsp)
	call	*__imp_OpenProcessToken(%rip)
	movl	%eax, %ebx
	testl	%eax, %eax
	jne	.L89
.L69:
	movq	104(%rsp), %rcx
	movq	__imp_CloseHandle(%rip), %rdx
	testq	%rcx, %rcx
	je	.L72
	movq	%rdx, 72(%rsp)
	call	*%rdx
	movq	72(%rsp), %rdx
.L72:
	movq	%rsi, %rcx
	call	*%rdx
.L67:
	movl	%ebx, %eax
	addq	$1144, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%r14
	ret
	.p2align 4,,10
	.p2align 3
.L89:
	leaq	88(%rsp), %r11
	movq	104(%rsp), %rcx
	xorl	%r9d, %r9d
	xorl	%r8d, %r8d
	movq	__imp_GetTokenInformation(%rip), %r10
	movq	%r11, 32(%rsp)
	movl	$1, %edx
	movl	$0, 88(%rsp)
	movq	%r10, 72(%rsp)
	call	*%r10
	movq	__imp_GetProcessHeap(%rip), %rax
	movl	88(%rsp), %ebx
	movq	%rax, %r14
	call	*%rax
	movq	%rbx, %r8
	xorl	%edx, %edx
	xorl	%ebx, %ebx
	movq	%rax, %rcx
	call	*__imp_HeapAlloc(%rip)
	movq	%rax, %rdi
	movq	%rax, %r8
	testq	%rax, %rax
	je	.L69
	leaq	88(%rsp), %r11
	movl	88(%rsp), %r9d
	movq	104(%rsp), %rcx
	movl	$1, %edx
	movq	%r11, 32(%rsp)
	call	*72(%rsp)
	movl	%eax, %ebx
	testl	%eax, %eax
	jne	.L90
.L70:
	call	*%r14
	movq	%rdi, %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
	jmp	.L69
	.p2align 4,,10
	.p2align 3
.L90:
	leaq	100(%rsp), %rax
	movq	(%rdi), %rdx
	leaq	92(%rsp), %r9
	xorl	%ecx, %ecx
	movq	%rax, 48(%rsp)
	leaq	624(%rsp), %r10
	leaq	96(%rsp), %rax
	movl	$256, 92(%rsp)
	leaq	112(%rsp), %r8
	movl	$256, 96(%rsp)
	movq	%rax, 40(%rsp)
	movq	%r10, 32(%rsp)
	call	*__imp_LookupAccountSidW(%rip)
	movl	%eax, %ebx
	testl	%eax, %eax
	je	.L70
	leaq	112(%rsp), %rax
	movl	1200(%rsp), %edx
	movq	1192(%rsp), %rcx
	leaq	624(%rsp), %r9
	movq	%rax, 32(%rsp)
	leaq	.LC23(%rip), %r8
	movl	$1, %ebx
	call	*__imp__snwprintf(%rip)
	jmp	.L70
	.seh_endproc
	.p2align 4
	.globl	GetProcessIntegrityRID
	.def	GetProcessIntegrityRID;	.scl	2;	.type	32;	.endef
	.seh_proc	GetProcessIntegrityRID
GetProcessIntegrityRID:
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$88, %rsp
	.seh_stackalloc	88
	.seh_endprologue
	movl	$8, %edx
	xorl	%ebx, %ebx
	movq	$0, 72(%rsp)
	leaq	72(%rsp), %r8
	call	*__imp_OpenProcessToken(%rip)
	testl	%eax, %eax
	jne	.L101
	movl	%ebx, %eax
	addq	$88, %rsp
	popq	%rbx
	popq	%rsi
	ret
	.p2align 4,,10
	.p2align 3
.L101:
	leaq	68(%rsp), %r11
	movq	72(%rsp), %rcx
	xorl	%r9d, %r9d
	xorl	%r8d, %r8d
	movq	__imp_GetTokenInformation(%rip), %r10
	movq	%r11, 32(%rsp)
	movl	$25, %edx
	movl	$0, 68(%rsp)
	movq	%r10, 56(%rsp)
	call	*%r10
	movl	68(%rsp), %r8d
	movq	__imp_GetProcessHeap(%rip), %rsi
	movq	%r8, 48(%rsp)
	call	*%rsi
	movq	48(%rsp), %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapAlloc(%rip)
	movq	%rax, %r8
	testq	%rax, %rax
	je	.L93
	leaq	68(%rsp), %r11
	movq	%rax, 48(%rsp)
	movl	68(%rsp), %r9d
	movl	$25, %edx
	movq	%r11, 32(%rsp)
	movq	72(%rsp), %rcx
	call	*56(%rsp)
	movq	48(%rsp), %r8
	testl	%eax, %eax
	jne	.L102
.L94:
	movq	%r8, 48(%rsp)
	call	*%rsi
	movq	48(%rsp), %r8
	xorl	%edx, %edx
	movq	%rax, %rcx
	call	*__imp_HeapFree(%rip)
.L93:
	movq	72(%rsp), %rcx
	call	*__imp_CloseHandle(%rip)
	movl	%ebx, %eax
	addq	$88, %rsp
	popq	%rbx
	popq	%rsi
	ret
	.p2align 4,,10
	.p2align 3
.L102:
	movq	(%r8), %rcx
	call	*__imp_GetSidSubAuthorityCount(%rip)
	movq	48(%rsp), %r8
	movzbl	(%rax), %edx
	movq	(%r8), %rcx
	subl	$1, %edx
	call	*__imp_GetSidSubAuthority(%rip)
	movq	48(%rsp), %r8
	movl	(%rax), %ebx
	jmp	.L94
	.seh_endproc
	.p2align 4
	.globl	IsProcessElevated
	.def	IsProcessElevated;	.scl	2;	.type	32;	.endef
	.seh_proc	IsProcessElevated
IsProcessElevated:
	subq	$88, %rsp
	.seh_stackalloc	88
	.seh_endprologue
	movl	$8, %edx
	movq	$0, 72(%rsp)
	leaq	72(%rsp), %r8
	call	*__imp_OpenProcessToken(%rip)
	movl	%eax, %edx
	testl	%eax, %eax
	jne	.L112
	movl	%edx, %eax
	addq	$88, %rsp
	ret
	.p2align 4,,10
	.p2align 3
.L112:
	leaq	68(%rsp), %rax
	movl	$20, %edx
	movq	72(%rsp), %rcx
	movl	$4, 68(%rsp)
	movq	%rax, 32(%rsp)
	movl	$4, %r9d
	leaq	64(%rsp), %r8
	call	*__imp_GetTokenInformation(%rip)
	movl	%eax, %edx
	testl	%eax, %eax
	je	.L105
	movl	64(%rsp), %eax
	xorl	%edx, %edx
	testl	%eax, %eax
	setne	%dl
.L105:
	movl	%edx, 60(%rsp)
	movq	72(%rsp), %rcx
	call	*__imp_CloseHandle(%rip)
	movl	60(%rsp), %edx
	movl	%edx, %eax
	addq	$88, %rsp
	ret
	.seh_endproc
	.p2align 4
	.globl	WcsContainsI
	.def	WcsContainsI;	.scl	2;	.type	32;	.endef
	.seh_proc	WcsContainsI
WcsContainsI:
	movl	$4664, %eax
	call	___chkstk_ms
	subq	%rax, %rsp
	.seh_stackalloc	4664
	.seh_endprologue
	testq	%rcx, %rcx
	je	.L115
	testq	%rdx, %rdx
	je	.L115
	movq	%rdx, 4680(%rsp)
	movl	$2047, %r8d
	movq	%rcx, %rdx
	leaq	560(%rsp), %rcx
	call	wcsncpy
	movq	4680(%rsp), %rdx
	movl	$255, %r8d
	xorl	%eax, %eax
	leaq	48(%rsp), %rcx
	movw	%ax, 4654(%rsp)
	call	wcsncpy
	xorl	%edx, %edx
	leaq	560(%rsp), %rcx
	movw	%dx, 558(%rsp)
	movq	__imp__wcslwr(%rip), %rdx
	movq	%rdx, 40(%rsp)
	call	*%rdx
	leaq	48(%rsp), %rcx
	call	*40(%rsp)
	leaq	48(%rsp), %rdx
	leaq	560(%rsp), %rcx
	call	wcsstr
	testq	%rax, %rax
	setne	%al
	movzbl	%al, %eax
	addq	$4664, %rsp
	ret
	.p2align 4,,10
	.p2align 3
.L115:
	xorl	%eax, %eax
	addq	$4664, %rsp
	ret
	.seh_endproc
	.p2align 4
	.globl	WcsSplit
	.def	WcsSplit;	.scl	2;	.type	32;	.endef
	.seh_proc	WcsSplit
WcsSplit:
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
	subq	$2128, %rsp
	.seh_stackalloc	2128
	.seh_endprologue
	movzwl	%dx, %esi
	movq	%r8, %rbp
	movq	%r9, %r12
	testq	%rcx, %rcx
	je	.L120
	testq	%r8, %r8
	je	.L120
	movq	%rcx, %rdx
	movl	$1039, %r8d
	leaq	48(%rsp), %rcx
	call	wcsncpy
	xorl	%ecx, %ecx
	movw	%cx, 2126(%rsp)
	cmpw	$0, 48(%rsp)
	je	.L120
	leaq	48(%rsp), %rbx
	xorl	%edi, %edi
	jmp	.L124
	.p2align 4,,10
	.p2align 3
.L121:
	xorl	%edx, %edx
	movw	%dx, (%rax)
	cmpw	$0, (%rbx)
	je	.L123
	movq	%rax, 40(%rsp)
	movq	%r12, %rdx
	movq	%rbx, %rcx
	addl	$1, %edi
	call	*%rbp
	movq	40(%rsp), %rax
.L123:
	leaq	2(%rax), %rbx
	cmpw	$0, 2(%rax)
	je	.L116
.L124:
	movl	%esi, %edx
	movq	%rbx, %rcx
	call	wcschr
	testq	%rax, %rax
	jne	.L121
	cmpw	$0, (%rbx)
	je	.L116
	addl	$1, %edi
	movq	%r12, %rdx
	movq	%rbx, %rcx
	call	*%rbp
	movl	%edi, %eax
	addq	$2128, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	popq	%r12
	ret
	.p2align 4,,10
	.p2align 3
.L120:
	xorl	%edi, %edi
.L116:
	movl	%edi, %eax
	addq	$2128, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	popq	%r12
	ret
	.seh_endproc
	.section .rdata,"dr"
	.align 2
.LC30:
	.ascii ".\0e\0x\0e\0\0\0"
	.text
	.p2align 4
	.globl	ExtractExePath
	.def	ExtractExePath;	.scl	2;	.type	32;	.endef
	.seh_proc	ExtractExePath
ExtractExePath:
	pushq	%rdi
	.seh_pushreg	%rdi
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$2112, %rsp
	.seh_stackalloc	2112
	.seh_endprologue
	movq	%rdx, %rsi
	leaq	32(%rsp), %rbx
	leaq	32(%rsp), %rdx
	movl	%r8d, %edi
	movl	$520, %r8d
	call	*__imp_ExpandEnvironmentStringsW(%rip)
	cmpw	$34, 32(%rsp)
	je	.L135
.L127:
	movl	$519, %r8d
	movq	%rbx, %rdx
	leaq	1072(%rsp), %rcx
	call	wcsncpy
	xorl	%edx, %edx
	leaq	1072(%rsp), %rcx
	movw	%dx, 2110(%rsp)
	call	*__imp__wcslwr(%rip)
	leaq	.LC30(%rip), %rdx
	leaq	1072(%rsp), %rcx
	call	wcsstr
	testq	%rax, %rax
	je	.L130
	leaq	1072(%rsp), %rdx
	leal	-1(%rdi), %r8d
	subq	%rdx, %rax
	sarq	%rax
	addl	$4, %eax
	cmpl	%edi, %eax
	movl	%eax, %edi
	cmovnb	%r8d, %edi
.L134:
	movq	%rdi, %r8
	movq	%rbx, %rdx
	movq	%rsi, %rcx
	call	wcsncpy
	xorl	%eax, %eax
	movw	%ax, (%rsi,%rdi,2)
	movl	$1, %eax
	addq	$2112, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	ret
	.p2align 4,,10
	.p2align 3
.L135:
	movl	$34, %edx
	leaq	34(%rsp), %rcx
	leaq	34(%rsp), %rbx
	call	wcschr
	testq	%rax, %rax
	je	.L127
	subq	%rbx, %rax
	leal	-1(%rdi), %ebx
	leaq	34(%rsp), %rdx
	movq	%rsi, %rcx
	sarq	%rax
	cmpl	%edi, %eax
	cmovb	%eax, %ebx
	movq	%rbx, %r8
	call	wcsncpy
	xorl	%ecx, %ecx
	movl	$1, %eax
	movw	%cx, (%rsi,%rbx,2)
	addq	$2112, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	ret
	.p2align 4,,10
	.p2align 3
.L130:
	subl	$1, %edi
	jmp	.L134
	.seh_endproc
	.globl	g_noColor
	.bss
	.align 4
g_noColor:
	.space 4
	.globl	g_outFile
	.align 8
g_outFile:
	.space 8
	.section .rdata,"dr"
	.align 16
.LC17:
	.long	1179785
	.long	1179926
	.long	1179808
	.long	2032127
	.align 16
.LC24:
	.long	131097
	.long	131078
	.long	0
	.long	983103
	.ident	"GCC: (Rev2, Built by MSYS2 project) 16.1.0"
	.def	wprintf;	.scl	2;	.type	32;	.endef
	.def	fwprintf;	.scl	2;	.type	32;	.endef
	.def	vwprintf;	.scl	2;	.type	32;	.endef
	.def	vfwprintf;	.scl	2;	.type	32;	.endef
	.def	wcsncpy;	.scl	2;	.type	32;	.endef
	.def	wcsstr;	.scl	2;	.type	32;	.endef
	.def	wcschr;	.scl	2;	.type	32;	.endef
