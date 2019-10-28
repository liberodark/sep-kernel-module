	.text
	.globl  symev_stub_execve
	.type   symev_stub_execve, @function

	symev_stub_execve:
#ifdef __x86_64__
	    pushq   %rbx
	    pushq   %rdi
	    pushq   %rsi
	    pushq   %rdx
	    pushq   %rcx
	    pushq   %rax
	    pushq   %r8
	    pushq   %r9
	    pushq   %r10
	    pushq   %r11

	    call    symev_execve
	    test    %rax, %rax
	    movq    %rax, %rbx

	    pop     %r11
	    pop     %r10
	    pop     %r9
	    pop     %r8
	    pop     %rax
	    pop     %rcx
	    pop     %rdx
	    pop     %rsi
	    pop     %rdi
	
	    jz      symev_stub_execve_done
	    
	    movq    %rbx, %rax
	    pop     %rbx
	    ret
	    
	symev_stub_execve_done:
	    pop     %rbx
	    jmp     *orig_stub_execve
#else //__x86_64__
            ret
#endif //__x86_64__
