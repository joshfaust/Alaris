.code

EXTERN SW2_GetSyscallNumber: PROC

NtCreateProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0E5B31BDFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateProcess ENDP

NtCreateThreadEx PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BCA11E9Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateThreadEx ENDP

NtOpenProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0CDAFC633h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcess ENDP

NtOpenProcessToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0859CF318h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcessToken ENDP

NtTestAlert PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00A81231Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTestAlert ENDP

NtOpenThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F6D6FA76h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenThread ENDP

NtSuspendProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 07DA3563Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSuspendProcess ENDP

NtSuspendThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0A4FF9E79h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSuspendThread ENDP

NtResumeProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 08D164244h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtResumeProcess ENDP

NtResumeThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 014CFDEE1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtResumeThread ENDP

NtGetContextThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 096325901h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetContextThread ENDP

NtSetContextThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 014A4CE02h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtSetContextThread ENDP

NtClose PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0041571FDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtClose ENDP

NtReadVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0C76DD9FBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReadVirtualMemory ENDP

NtWriteVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F79AEF1Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWriteVirtualMemory ENDP

NtAllocateVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0BF2AD7CBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 04BD04557h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtProtectVirtualMemory ENDP

NtFreeVirtualMemory PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 000126CF7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFreeVirtualMemory ENDP

NtQuerySystemInformation PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0149A4E5Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySystemInformation ENDP

NtQueryDirectoryFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 031980F03h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryDirectoryFile ENDP

NtQueryInformationFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 024BC0BEEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationFile ENDP

NtQueryInformationProcess PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 071DF7A40h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationProcess ENDP

NtQueryInformationThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00494444Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationThread ENDP

NtCreateSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0FFA4C30Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateSection ENDP

NtOpenSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00AA2540Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenSection ENDP

NtMapViewOfSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 008922A43h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtMapViewOfSection ENDP

NtUnmapViewOfSection PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0870CC7DEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtUnmapViewOfSection ENDP

NtAdjustPrivilegesToken PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 00596173Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAdjustPrivilegesToken ENDP

NtDeviceIoControlFile PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0B71E878Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeviceIoControlFile ENDP

NtQueueApcThread PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0964E4A77h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueueApcThread ENDP

NtWaitForMultipleObjects PROC
	push rcx                   ; Save registers.
	push rdx
	push r8
	push r9
	mov ecx, 0F5BB0CD6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	pop r9                     ; Restore registers.
	pop r8
	pop rdx
	pop rcx
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForMultipleObjects ENDP

end