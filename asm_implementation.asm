[bits 64]

global enable_vmx
global disable_vmx
global start_vmx
global clear_vmcs
global load_vmcs
global read_vmcs
global write_vmcs
global stop_vmx
global get_cr0
global get_cr2
global get_cr3
global set_cr3
global get_cr4
global set_cr4
global get_cr8
global get_cs
global get_ss
global hu_get_ds
global get_es
global hu_get_fs
global get_gs
global get_tr
global get_dr7
global get_rflags
global get_ldtr
global cu_read_msr
global vm_launch
global resume
global calc_vm_exit_callback_addr
global vm_exit_callback_stub
global do_invd
global pause_loop
global restore_context_from_stack


extern vm_exit_callback
extern vm_resume_fail_callback


%macro PUSHAQ 0
	push rbp
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
%endmacro

%macro POPAQ 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	pop rbp
%endmacro

enable_vmx:
	mov rax, cr4
	bts rax, 13
	mov cr4, rax
	ret

disable_vmx:
	mov rax, cr4
	btc rax, 13
	mov cr4, rax
	ret

start_vmx:
	vmxon [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

stop_vmx:
	vmxoff
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
clear_vmcs:
	vmclear [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

load_vmcs:
	vmptrld [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

write_vmcs:
	vmwrite rdi, rsi
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

read_vmcs:
	vmread [rsi], rdi
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

get_cr0:
	mov rax, cr0
	ret


get_cr2:
	mov rax, cr2
	ret

get_cr3:
	mov rax, cr3
	ret

get_cr4:
	mov rax, cr4
	ret

get_cr8:
	mov rax, cr8
	ret

get_cs:
	mov rax, cs
	ret

get_ss:
	mov rax, ss
	ret

hu_get_ds:
	mov rax, ds
	ret

get_es:
	mov rax, es
	ret

hu_get_fs:
	mov rax, fs
	ret

get_gs:
	mov rax, gs
	ret

get_tr:
	str rax
	ret

get_dr7:
	mov rax, dr7
	ret

get_rflags:
	pushfq
	pop rax
	ret

get_ldtr:
	sldt rax
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
set_cr4:
	mov cr4, rdi
	ret

set_cr3:
	mov cr3, rdi
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
vm_launch:
	push rbx

	; For seamless interoperation, set RSP of the guest to the host.
	mov rbx, 0x681C		; RSP
	mov rax, rsp
	vmwrite rbx, rax
	
	; Get current RIP.
	call .get_rip
.get_rip:
	pop rax
	
	mov rbx, 0x681E		; RIP
	add rax, (.success - .get_rip)
	vmwrite rbx, rax

	vmlaunch

	; Process fail.
	pop rbx

	jc .errorInvalid
	jz .errorValid

	mov rax, 0
	jmp .end

.errorInvalid:
	mov rax, -1
	jmp .end

.errorValid:
	mov rax, -2

.end:
	ret

.success:
	; Start line of the guest.
	; Now the core is in the guest.
	pop rbx
	mov rax, 0
	ret

; When VM exit occur, RFLAGS is cleared except bit 1.
vm_exit_callback_stub:
	; Start line of the host.
	; Now the core is in the host.
	PUSHAQ
	
	; RDI has the pointer of the guest context structure.
	mov rdi, rsp

	call vm_exit_callback
	
	; Resume the guest.
	POPAQ
	vmresume

	; Error occur.
	mov rdi, rax
	call vm_resume_fail_callback

.hang:
	jmp .hang
	ret

; Process INVD.
do_invd:
	invd
	ret

; Pause CPU.
pause_loop:
	pause
	ret

; Restore context from stack(vm_full_context).
restore_context_from_stack:
	mov rsp, rdi
	
	pop rax			; cr4
	;mov cr4, rax

	pop rax			; cr3
	mov cr3, rax

	pop rax			; cr0
	;mov cr0, rax

	pop rax			; tr
	;ltr ax

	pop rax			; lldt
	;lldt ax

	pop rax			; gs
	;mov gs, ax

	pop rax			; fs
	mov fs, ax

	pop rax			; es
	mov es, ax

	pop rax			; ds
	mov ds, ax

	pop rax			; cs
	;ignore cs

	POPAQ			; Restore GP register.
	popfq			; Restore RFLAGS.

	ret				; Return to RIP.

cu_read_msr:
	push rdx
	push rcx

	xor rdx, rdx
	xor rax, rax

	mov ecx, edi
	rdmsr

	shl rdx, 32
	or rax, rdx

	pop rcx
	pop rdx
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;