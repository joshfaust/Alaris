.code

NtCreateProcess PROC
	mov rax, gs:[60h]                         ; Load PEB into RAX.
NtCreateProcess_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtCreateProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtCreateProcess_Check_10_0_XXXX
	jmp NtCreateProcess_SystemCall_Unknown
NtCreateProcess_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtCreateProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateProcess_SystemCall_6_3_XXXX
	jmp NtCreateProcess_SystemCall_Unknown
NtCreateProcess_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtCreateProcess_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtCreateProcess_SystemCall_6_1_7601
	jmp NtCreateProcess_SystemCall_Unknown
NtCreateProcess_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtCreateProcess_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtCreateProcess_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtCreateProcess_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtCreateProcess_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtCreateProcess_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtCreateProcess_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtCreateProcess_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtCreateProcess_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtCreateProcess_SystemCall_10_0_18363
	jmp NtCreateProcess_SystemCall_Unknown
NtCreateProcess_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 009fh
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 009fh
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 00a9h
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 00aah
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 00adh
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 00aeh
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 00afh
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 00b2h
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 00b3h
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 00b4h
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 00b4h
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 00b5h
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 00b5h
	jmp NtCreateProcess_Epilogue
NtCreateProcess_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtCreateProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtCreateProcess ENDP

NtCreateThreadEx PROC
	mov rax, gs:[60h]                          ; Load PEB into RAX.
NtCreateThreadEx_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtCreateThreadEx_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtCreateThreadEx_Check_10_0_XXXX
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtCreateThreadEx_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateThreadEx_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateThreadEx_SystemCall_6_3_XXXX
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtCreateThreadEx_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtCreateThreadEx_SystemCall_6_1_7601
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtCreateThreadEx_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtCreateThreadEx_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtCreateThreadEx_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtCreateThreadEx_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtCreateThreadEx_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtCreateThreadEx_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtCreateThreadEx_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtCreateThreadEx_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtCreateThreadEx_SystemCall_10_0_18363
	jmp NtCreateThreadEx_SystemCall_Unknown
NtCreateThreadEx_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 00a5h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 00a5h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 00afh
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 00b0h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 00b3h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 00b4h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 00b6h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 00b9h
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 00bah
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 00bbh
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 00bch
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 00bdh
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 00bdh
	jmp NtCreateThreadEx_Epilogue
NtCreateThreadEx_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtCreateThreadEx_Epilogue:
	mov r10, rcx
	syscall
	ret
NtCreateThreadEx ENDP

NtOpenProcess PROC
	mov rax, gs:[60h]                       ; Load PEB into RAX.
NtOpenProcess_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtOpenProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenProcess_Check_10_0_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtOpenProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenProcess_SystemCall_6_3_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtOpenProcess_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtOpenProcess_SystemCall_6_1_7601
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtOpenProcess_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtOpenProcess_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtOpenProcess_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtOpenProcess_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtOpenProcess_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtOpenProcess_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtOpenProcess_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtOpenProcess_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtOpenProcess_SystemCall_10_0_18363
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0023h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0024h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0025h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0026h
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenProcess ENDP

NtOpenThread PROC
	mov rax, gs:[60h]                      ; Load PEB into RAX.
NtOpenThread_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtOpenThread_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenThread_Check_10_0_XXXX
	jmp NtOpenThread_SystemCall_Unknown
NtOpenThread_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtOpenThread_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenThread_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenThread_SystemCall_6_3_XXXX
	jmp NtOpenThread_SystemCall_Unknown
NtOpenThread_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtOpenThread_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtOpenThread_SystemCall_6_1_7601
	jmp NtOpenThread_SystemCall_Unknown
NtOpenThread_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtOpenThread_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtOpenThread_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtOpenThread_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtOpenThread_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtOpenThread_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtOpenThread_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtOpenThread_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtOpenThread_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtOpenThread_SystemCall_10_0_18363
	jmp NtOpenThread_SystemCall_Unknown
NtOpenThread_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 00feh
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 00feh
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0110h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0113h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0119h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 011ch
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 011fh
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0123h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0125h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0127h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0128h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0129h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0129h
	jmp NtOpenThread_Epilogue
NtOpenThread_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtOpenThread_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenThread ENDP

NtSuspendProcess PROC
	mov rax, gs:[60h]                          ; Load PEB into RAX.
NtSuspendProcess_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtSuspendProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtSuspendProcess_Check_10_0_XXXX
	jmp NtSuspendProcess_SystemCall_Unknown
NtSuspendProcess_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtSuspendProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtSuspendProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtSuspendProcess_SystemCall_6_3_XXXX
	jmp NtSuspendProcess_SystemCall_Unknown
NtSuspendProcess_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtSuspendProcess_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtSuspendProcess_SystemCall_6_1_7601
	jmp NtSuspendProcess_SystemCall_Unknown
NtSuspendProcess_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtSuspendProcess_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtSuspendProcess_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtSuspendProcess_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtSuspendProcess_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtSuspendProcess_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtSuspendProcess_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtSuspendProcess_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtSuspendProcess_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtSuspendProcess_SystemCall_10_0_18363
	jmp NtSuspendProcess_SystemCall_Unknown
NtSuspendProcess_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 017ah
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 017ah
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0192h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0197h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 019fh
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 01a2h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 01a8h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 01aeh
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 01b1h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 01b3h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 01b4h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 01b5h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 01b5h
	jmp NtSuspendProcess_Epilogue
NtSuspendProcess_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtSuspendProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtSuspendProcess ENDP

NtSuspendThread PROC
	mov rax, gs:[60h]                         ; Load PEB into RAX.
NtSuspendThread_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtSuspendThread_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtSuspendThread_Check_10_0_XXXX
	jmp NtSuspendThread_SystemCall_Unknown
NtSuspendThread_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtSuspendThread_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtSuspendThread_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtSuspendThread_SystemCall_6_3_XXXX
	jmp NtSuspendThread_SystemCall_Unknown
NtSuspendThread_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtSuspendThread_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtSuspendThread_SystemCall_6_1_7601
	jmp NtSuspendThread_SystemCall_Unknown
NtSuspendThread_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtSuspendThread_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtSuspendThread_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtSuspendThread_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtSuspendThread_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtSuspendThread_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtSuspendThread_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtSuspendThread_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtSuspendThread_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtSuspendThread_SystemCall_10_0_18363
	jmp NtSuspendThread_SystemCall_Unknown
NtSuspendThread_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 017bh
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 017bh
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0193h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0198h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 01a0h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 01a3h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 01a9h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 01afh
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 01b2h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 01b4h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 01b5h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 01b6h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 01b6h
	jmp NtSuspendThread_Epilogue
NtSuspendThread_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtSuspendThread_Epilogue:
	mov r10, rcx
	syscall
	ret
NtSuspendThread ENDP

NtResumeProcess PROC
	mov rax, gs:[60h]                         ; Load PEB into RAX.
NtResumeProcess_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtResumeProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtResumeProcess_Check_10_0_XXXX
	jmp NtResumeProcess_SystemCall_Unknown
NtResumeProcess_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtResumeProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtResumeProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtResumeProcess_SystemCall_6_3_XXXX
	jmp NtResumeProcess_SystemCall_Unknown
NtResumeProcess_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtResumeProcess_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtResumeProcess_SystemCall_6_1_7601
	jmp NtResumeProcess_SystemCall_Unknown
NtResumeProcess_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtResumeProcess_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtResumeProcess_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtResumeProcess_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtResumeProcess_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtResumeProcess_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtResumeProcess_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtResumeProcess_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtResumeProcess_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtResumeProcess_SystemCall_10_0_18363
	jmp NtResumeProcess_SystemCall_Unknown
NtResumeProcess_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0144h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0144h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0158h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 015bh
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0161h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0164h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0168h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 016eh
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0171h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0173h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0174h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0175h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0175h
	jmp NtResumeProcess_Epilogue
NtResumeProcess_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtResumeProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtResumeProcess ENDP

NtResumeThread PROC
	mov rax, gs:[60h]                        ; Load PEB into RAX.
NtResumeThread_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtResumeThread_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtResumeThread_Check_10_0_XXXX
	jmp NtResumeThread_SystemCall_Unknown
NtResumeThread_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtResumeThread_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtResumeThread_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtResumeThread_SystemCall_6_3_XXXX
	jmp NtResumeThread_SystemCall_Unknown
NtResumeThread_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtResumeThread_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtResumeThread_SystemCall_6_1_7601
	jmp NtResumeThread_SystemCall_Unknown
NtResumeThread_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtResumeThread_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtResumeThread_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtResumeThread_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtResumeThread_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtResumeThread_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtResumeThread_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtResumeThread_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtResumeThread_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtResumeThread_SystemCall_10_0_18363
	jmp NtResumeThread_SystemCall_Unknown
NtResumeThread_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 004fh
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 004fh
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0050h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0051h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0052h
	jmp NtResumeThread_Epilogue
NtResumeThread_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtResumeThread_Epilogue:
	mov r10, rcx
	syscall
	ret
NtResumeThread ENDP

NtGetContextThread PROC
	mov rax, gs:[60h]                            ; Load PEB into RAX.
NtGetContextThread_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtGetContextThread_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtGetContextThread_Check_10_0_XXXX
	jmp NtGetContextThread_SystemCall_Unknown
NtGetContextThread_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtGetContextThread_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtGetContextThread_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtGetContextThread_SystemCall_6_3_XXXX
	jmp NtGetContextThread_SystemCall_Unknown
NtGetContextThread_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtGetContextThread_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtGetContextThread_SystemCall_6_1_7601
	jmp NtGetContextThread_SystemCall_Unknown
NtGetContextThread_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtGetContextThread_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtGetContextThread_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtGetContextThread_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtGetContextThread_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtGetContextThread_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtGetContextThread_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtGetContextThread_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtGetContextThread_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtGetContextThread_SystemCall_10_0_18363
	jmp NtGetContextThread_SystemCall_Unknown
NtGetContextThread_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 00cah
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 00cah
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 00ddh
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 00e0h
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 00e3h
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 00e4h
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 00e6h
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 00e9h
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 00eah
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 00ebh
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 00ech
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 00edh
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 00edh
	jmp NtGetContextThread_Epilogue
NtGetContextThread_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtGetContextThread_Epilogue:
	mov r10, rcx
	syscall
	ret
NtGetContextThread ENDP

NtSetContextThread PROC
	mov rax, gs:[60h]                            ; Load PEB into RAX.
NtSetContextThread_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtSetContextThread_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtSetContextThread_Check_10_0_XXXX
	jmp NtSetContextThread_SystemCall_Unknown
NtSetContextThread_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtSetContextThread_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtSetContextThread_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtSetContextThread_SystemCall_6_3_XXXX
	jmp NtSetContextThread_SystemCall_Unknown
NtSetContextThread_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtSetContextThread_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtSetContextThread_SystemCall_6_1_7601
	jmp NtSetContextThread_SystemCall_Unknown
NtSetContextThread_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtSetContextThread_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtSetContextThread_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtSetContextThread_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtSetContextThread_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtSetContextThread_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtSetContextThread_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtSetContextThread_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtSetContextThread_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtSetContextThread_SystemCall_10_0_18363
	jmp NtSetContextThread_SystemCall_Unknown
NtSetContextThread_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0150h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0150h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0165h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0168h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 016fh
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0172h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0178h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 017eh
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0181h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0183h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0184h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0185h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0185h
	jmp NtSetContextThread_Epilogue
NtSetContextThread_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtSetContextThread_Epilogue:
	mov r10, rcx
	syscall
	ret
NtSetContextThread ENDP

NtClose PROC
	mov rax, gs:[60h]                 ; Load PEB into RAX.
NtClose_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtClose_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtClose_Check_10_0_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtClose_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtClose_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtClose_SystemCall_6_3_XXXX
	jmp NtClose_SystemCall_Unknown
NtClose_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtClose_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtClose_SystemCall_6_1_7601
	jmp NtClose_SystemCall_Unknown
NtClose_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtClose_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtClose_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtClose_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtClose_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtClose_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtClose_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtClose_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtClose_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtClose_SystemCall_10_0_18363
	jmp NtClose_SystemCall_Unknown
NtClose_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 000ch
	jmp NtClose_Epilogue
NtClose_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 000dh
	jmp NtClose_Epilogue
NtClose_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 000eh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 000fh
	jmp NtClose_Epilogue
NtClose_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtClose_Epilogue:
	mov r10, rcx
	syscall
	ret
NtClose ENDP

NtReadVirtualMemory PROC
	mov rax, gs:[60h]                             ; Load PEB into RAX.
NtReadVirtualMemory_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtReadVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtReadVirtualMemory_Check_10_0_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtReadVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtReadVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtReadVirtualMemory_SystemCall_6_3_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtReadVirtualMemory_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtReadVirtualMemory_SystemCall_6_1_7601
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtReadVirtualMemory_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtReadVirtualMemory_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtReadVirtualMemory_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtReadVirtualMemory_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtReadVirtualMemory_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtReadVirtualMemory_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtReadVirtualMemory_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtReadVirtualMemory_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtReadVirtualMemory_SystemCall_10_0_18363
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 003ch
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 003dh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 003eh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtReadVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtReadVirtualMemory ENDP

NtWriteVirtualMemory PROC
	mov rax, gs:[60h]                              ; Load PEB into RAX.
NtWriteVirtualMemory_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtWriteVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtWriteVirtualMemory_Check_10_0_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtWriteVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtWriteVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtWriteVirtualMemory_SystemCall_6_3_XXXX
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtWriteVirtualMemory_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtWriteVirtualMemory_SystemCall_6_1_7601
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtWriteVirtualMemory_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtWriteVirtualMemory_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtWriteVirtualMemory_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtWriteVirtualMemory_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtWriteVirtualMemory_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtWriteVirtualMemory_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtWriteVirtualMemory_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtWriteVirtualMemory_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtWriteVirtualMemory_SystemCall_10_0_18363
	jmp NtWriteVirtualMemory_SystemCall_Unknown
NtWriteVirtualMemory_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0037h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0037h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0038h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0039h
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 003ah
	jmp NtWriteVirtualMemory_Epilogue
NtWriteVirtualMemory_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtWriteVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtWriteVirtualMemory ENDP

NtAllocateVirtualMemory PROC
	mov rax, gs:[60h]                                 ; Load PEB into RAX.
NtAllocateVirtualMemory_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtAllocateVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtAllocateVirtualMemory_Check_10_0_XXXX
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtAllocateVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtAllocateVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtAllocateVirtualMemory_SystemCall_6_3_XXXX
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtAllocateVirtualMemory_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtAllocateVirtualMemory_SystemCall_6_1_7601
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtAllocateVirtualMemory_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtAllocateVirtualMemory_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtAllocateVirtualMemory_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtAllocateVirtualMemory_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtAllocateVirtualMemory_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtAllocateVirtualMemory_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtAllocateVirtualMemory_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtAllocateVirtualMemory_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtAllocateVirtualMemory_SystemCall_10_0_18363
	jmp NtAllocateVirtualMemory_SystemCall_Unknown
NtAllocateVirtualMemory_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0015h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0015h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0016h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0017h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0018h
	jmp NtAllocateVirtualMemory_Epilogue
NtAllocateVirtualMemory_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtAllocateVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
	mov rax, gs:[60h]                                ; Load PEB into RAX.
NtProtectVirtualMemory_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtProtectVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtProtectVirtualMemory_Check_10_0_XXXX
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtProtectVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtProtectVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtProtectVirtualMemory_SystemCall_6_3_XXXX
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtProtectVirtualMemory_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtProtectVirtualMemory_SystemCall_6_1_7601
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtProtectVirtualMemory_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtProtectVirtualMemory_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtProtectVirtualMemory_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtProtectVirtualMemory_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtProtectVirtualMemory_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtProtectVirtualMemory_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtProtectVirtualMemory_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtProtectVirtualMemory_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtProtectVirtualMemory_SystemCall_10_0_18363
	jmp NtProtectVirtualMemory_SystemCall_Unknown
NtProtectVirtualMemory_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 004dh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 004dh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 004eh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 004fh
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0050h
	jmp NtProtectVirtualMemory_Epilogue
NtProtectVirtualMemory_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtProtectVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtProtectVirtualMemory ENDP

NtFreeVirtualMemory PROC
	mov rax, gs:[60h]                             ; Load PEB into RAX.
NtFreeVirtualMemory_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtFreeVirtualMemory_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtFreeVirtualMemory_Check_10_0_XXXX
	jmp NtFreeVirtualMemory_SystemCall_Unknown
NtFreeVirtualMemory_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtFreeVirtualMemory_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtFreeVirtualMemory_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtFreeVirtualMemory_SystemCall_6_3_XXXX
	jmp NtFreeVirtualMemory_SystemCall_Unknown
NtFreeVirtualMemory_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtFreeVirtualMemory_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtFreeVirtualMemory_SystemCall_6_1_7601
	jmp NtFreeVirtualMemory_SystemCall_Unknown
NtFreeVirtualMemory_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtFreeVirtualMemory_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtFreeVirtualMemory_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtFreeVirtualMemory_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtFreeVirtualMemory_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtFreeVirtualMemory_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtFreeVirtualMemory_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtFreeVirtualMemory_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtFreeVirtualMemory_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtFreeVirtualMemory_SystemCall_10_0_18363
	jmp NtFreeVirtualMemory_SystemCall_Unknown
NtFreeVirtualMemory_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 001bh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 001bh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 001ch
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 001dh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 001eh
	jmp NtFreeVirtualMemory_Epilogue
NtFreeVirtualMemory_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtFreeVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtFreeVirtualMemory ENDP

NtQuerySystemInformation PROC
	mov rax, gs:[60h]                                  ; Load PEB into RAX.
NtQuerySystemInformation_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtQuerySystemInformation_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQuerySystemInformation_Check_10_0_XXXX
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtQuerySystemInformation_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQuerySystemInformation_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQuerySystemInformation_SystemCall_6_3_XXXX
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtQuerySystemInformation_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtQuerySystemInformation_SystemCall_6_1_7601
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtQuerySystemInformation_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtQuerySystemInformation_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtQuerySystemInformation_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtQuerySystemInformation_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtQuerySystemInformation_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtQuerySystemInformation_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtQuerySystemInformation_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtQuerySystemInformation_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtQuerySystemInformation_SystemCall_10_0_18363
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0033h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0033h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0034h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0035h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0036h
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtQuerySystemInformation_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQuerySystemInformation ENDP

NtQueryDirectoryFile PROC
	mov rax, gs:[60h]                              ; Load PEB into RAX.
NtQueryDirectoryFile_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtQueryDirectoryFile_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQueryDirectoryFile_Check_10_0_XXXX
	jmp NtQueryDirectoryFile_SystemCall_Unknown
NtQueryDirectoryFile_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtQueryDirectoryFile_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryDirectoryFile_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryDirectoryFile_SystemCall_6_3_XXXX
	jmp NtQueryDirectoryFile_SystemCall_Unknown
NtQueryDirectoryFile_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtQueryDirectoryFile_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtQueryDirectoryFile_SystemCall_6_1_7601
	jmp NtQueryDirectoryFile_SystemCall_Unknown
NtQueryDirectoryFile_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtQueryDirectoryFile_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtQueryDirectoryFile_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtQueryDirectoryFile_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtQueryDirectoryFile_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtQueryDirectoryFile_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtQueryDirectoryFile_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtQueryDirectoryFile_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtQueryDirectoryFile_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtQueryDirectoryFile_SystemCall_10_0_18363
	jmp NtQueryDirectoryFile_SystemCall_Unknown
NtQueryDirectoryFile_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0032h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0032h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0033h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0034h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0035h
	jmp NtQueryDirectoryFile_Epilogue
NtQueryDirectoryFile_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtQueryDirectoryFile_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQueryDirectoryFile ENDP

NtQueryInformationFile PROC
	mov rax, gs:[60h]                                ; Load PEB into RAX.
NtQueryInformationFile_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtQueryInformationFile_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQueryInformationFile_Check_10_0_XXXX
	jmp NtQueryInformationFile_SystemCall_Unknown
NtQueryInformationFile_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtQueryInformationFile_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryInformationFile_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryInformationFile_SystemCall_6_3_XXXX
	jmp NtQueryInformationFile_SystemCall_Unknown
NtQueryInformationFile_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtQueryInformationFile_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtQueryInformationFile_SystemCall_6_1_7601
	jmp NtQueryInformationFile_SystemCall_Unknown
NtQueryInformationFile_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtQueryInformationFile_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtQueryInformationFile_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtQueryInformationFile_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtQueryInformationFile_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtQueryInformationFile_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtQueryInformationFile_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtQueryInformationFile_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtQueryInformationFile_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtQueryInformationFile_SystemCall_10_0_18363
	jmp NtQueryInformationFile_SystemCall_Unknown
NtQueryInformationFile_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 000eh
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 000eh
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 000fh
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0010h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0011h
	jmp NtQueryInformationFile_Epilogue
NtQueryInformationFile_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtQueryInformationFile_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQueryInformationFile ENDP

NtQueryInformationProcess PROC
	mov rax, gs:[60h]                                   ; Load PEB into RAX.
NtQueryInformationProcess_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtQueryInformationProcess_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQueryInformationProcess_Check_10_0_XXXX
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtQueryInformationProcess_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryInformationProcess_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryInformationProcess_SystemCall_6_3_XXXX
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtQueryInformationProcess_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtQueryInformationProcess_SystemCall_6_1_7601
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtQueryInformationProcess_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtQueryInformationProcess_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtQueryInformationProcess_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtQueryInformationProcess_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtQueryInformationProcess_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtQueryInformationProcess_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtQueryInformationProcess_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtQueryInformationProcess_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtQueryInformationProcess_SystemCall_10_0_18363
	jmp NtQueryInformationProcess_SystemCall_Unknown
NtQueryInformationProcess_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0016h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0016h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0017h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0018h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0019h
	jmp NtQueryInformationProcess_Epilogue
NtQueryInformationProcess_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtQueryInformationProcess_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQueryInformationProcess ENDP

NtQueryInformationThread PROC
	mov rax, gs:[60h]                                  ; Load PEB into RAX.
NtQueryInformationThread_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtQueryInformationThread_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQueryInformationThread_Check_10_0_XXXX
	jmp NtQueryInformationThread_SystemCall_Unknown
NtQueryInformationThread_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtQueryInformationThread_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryInformationThread_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueryInformationThread_SystemCall_6_3_XXXX
	jmp NtQueryInformationThread_SystemCall_Unknown
NtQueryInformationThread_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtQueryInformationThread_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtQueryInformationThread_SystemCall_6_1_7601
	jmp NtQueryInformationThread_SystemCall_Unknown
NtQueryInformationThread_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtQueryInformationThread_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtQueryInformationThread_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtQueryInformationThread_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtQueryInformationThread_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtQueryInformationThread_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtQueryInformationThread_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtQueryInformationThread_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtQueryInformationThread_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtQueryInformationThread_SystemCall_10_0_18363
	jmp NtQueryInformationThread_SystemCall_Unknown
NtQueryInformationThread_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0022h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0022h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0023h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0024h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0025h
	jmp NtQueryInformationThread_Epilogue
NtQueryInformationThread_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtQueryInformationThread_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQueryInformationThread ENDP

NtCreateSection PROC
	mov rax, gs:[60h]                         ; Load PEB into RAX.
NtCreateSection_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtCreateSection_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtCreateSection_Check_10_0_XXXX
	jmp NtCreateSection_SystemCall_Unknown
NtCreateSection_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtCreateSection_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateSection_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtCreateSection_SystemCall_6_3_XXXX
	jmp NtCreateSection_SystemCall_Unknown
NtCreateSection_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtCreateSection_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtCreateSection_SystemCall_6_1_7601
	jmp NtCreateSection_SystemCall_Unknown
NtCreateSection_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtCreateSection_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtCreateSection_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtCreateSection_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtCreateSection_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtCreateSection_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtCreateSection_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtCreateSection_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtCreateSection_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtCreateSection_SystemCall_10_0_18363
	jmp NtCreateSection_SystemCall_Unknown
NtCreateSection_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0047h
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0047h
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0048h
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0049h
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 004ah
	jmp NtCreateSection_Epilogue
NtCreateSection_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtCreateSection_Epilogue:
	mov r10, rcx
	syscall
	ret
NtCreateSection ENDP

NtOpenSection PROC
	mov rax, gs:[60h]                       ; Load PEB into RAX.
NtOpenSection_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtOpenSection_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtOpenSection_Check_10_0_XXXX
	jmp NtOpenSection_SystemCall_Unknown
NtOpenSection_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtOpenSection_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenSection_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtOpenSection_SystemCall_6_3_XXXX
	jmp NtOpenSection_SystemCall_Unknown
NtOpenSection_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtOpenSection_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtOpenSection_SystemCall_6_1_7601
	jmp NtOpenSection_SystemCall_Unknown
NtOpenSection_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtOpenSection_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtOpenSection_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtOpenSection_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtOpenSection_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtOpenSection_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtOpenSection_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtOpenSection_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtOpenSection_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtOpenSection_SystemCall_10_0_18363
	jmp NtOpenSection_SystemCall_Unknown
NtOpenSection_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0034h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0034h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0035h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0036h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0037h
	jmp NtOpenSection_Epilogue
NtOpenSection_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtOpenSection_Epilogue:
	mov r10, rcx
	syscall
	ret
NtOpenSection ENDP

NtMapViewOfSection PROC
	mov rax, gs:[60h]                            ; Load PEB into RAX.
NtMapViewOfSection_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtMapViewOfSection_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtMapViewOfSection_Check_10_0_XXXX
	jmp NtMapViewOfSection_SystemCall_Unknown
NtMapViewOfSection_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtMapViewOfSection_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtMapViewOfSection_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtMapViewOfSection_SystemCall_6_3_XXXX
	jmp NtMapViewOfSection_SystemCall_Unknown
NtMapViewOfSection_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtMapViewOfSection_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtMapViewOfSection_SystemCall_6_1_7601
	jmp NtMapViewOfSection_SystemCall_Unknown
NtMapViewOfSection_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtMapViewOfSection_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtMapViewOfSection_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtMapViewOfSection_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtMapViewOfSection_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtMapViewOfSection_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtMapViewOfSection_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtMapViewOfSection_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtMapViewOfSection_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtMapViewOfSection_SystemCall_10_0_18363
	jmp NtMapViewOfSection_SystemCall_Unknown
NtMapViewOfSection_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0025h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0025h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0026h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0027h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0028h
	jmp NtMapViewOfSection_Epilogue
NtMapViewOfSection_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtMapViewOfSection_Epilogue:
	mov r10, rcx
	syscall
	ret
NtMapViewOfSection ENDP

NtUnmapViewOfSection PROC
	mov rax, gs:[60h]                              ; Load PEB into RAX.
NtUnmapViewOfSection_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtUnmapViewOfSection_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtUnmapViewOfSection_Check_10_0_XXXX
	jmp NtUnmapViewOfSection_SystemCall_Unknown
NtUnmapViewOfSection_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtUnmapViewOfSection_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtUnmapViewOfSection_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtUnmapViewOfSection_SystemCall_6_3_XXXX
	jmp NtUnmapViewOfSection_SystemCall_Unknown
NtUnmapViewOfSection_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtUnmapViewOfSection_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtUnmapViewOfSection_SystemCall_6_1_7601
	jmp NtUnmapViewOfSection_SystemCall_Unknown
NtUnmapViewOfSection_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtUnmapViewOfSection_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtUnmapViewOfSection_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtUnmapViewOfSection_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtUnmapViewOfSection_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtUnmapViewOfSection_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtUnmapViewOfSection_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtUnmapViewOfSection_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtUnmapViewOfSection_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtUnmapViewOfSection_SystemCall_10_0_18363
	jmp NtUnmapViewOfSection_SystemCall_Unknown
NtUnmapViewOfSection_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0027h
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0027h
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0028h
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0029h
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 002ah
	jmp NtUnmapViewOfSection_Epilogue
NtUnmapViewOfSection_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtUnmapViewOfSection_Epilogue:
	mov r10, rcx
	syscall
	ret
NtUnmapViewOfSection ENDP

NtAdjustPrivilegesToken PROC
	mov rax, gs:[60h]                                 ; Load PEB into RAX.
NtAdjustPrivilegesToken_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtAdjustPrivilegesToken_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtAdjustPrivilegesToken_Check_10_0_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtAdjustPrivilegesToken_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtAdjustPrivilegesToken_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtAdjustPrivilegesToken_SystemCall_6_3_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7601
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtAdjustPrivilegesToken_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtAdjustPrivilegesToken_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtAdjustPrivilegesToken_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18363
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 003eh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 003fh
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0040h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0041h
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtAdjustPrivilegesToken_Epilogue:
	mov r10, rcx
	syscall
	ret
NtAdjustPrivilegesToken ENDP

NtDeviceIoControlFile PROC
	mov rax, gs:[60h]                               ; Load PEB into RAX.
NtDeviceIoControlFile_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtDeviceIoControlFile_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtDeviceIoControlFile_Check_10_0_XXXX
	jmp NtDeviceIoControlFile_SystemCall_Unknown
NtDeviceIoControlFile_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtDeviceIoControlFile_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtDeviceIoControlFile_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtDeviceIoControlFile_SystemCall_6_3_XXXX
	jmp NtDeviceIoControlFile_SystemCall_Unknown
NtDeviceIoControlFile_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtDeviceIoControlFile_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtDeviceIoControlFile_SystemCall_6_1_7601
	jmp NtDeviceIoControlFile_SystemCall_Unknown
NtDeviceIoControlFile_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtDeviceIoControlFile_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtDeviceIoControlFile_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtDeviceIoControlFile_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtDeviceIoControlFile_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtDeviceIoControlFile_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtDeviceIoControlFile_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtDeviceIoControlFile_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtDeviceIoControlFile_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtDeviceIoControlFile_SystemCall_10_0_18363
	jmp NtDeviceIoControlFile_SystemCall_Unknown
NtDeviceIoControlFile_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0004h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0004h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0005h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0006h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0007h
	jmp NtDeviceIoControlFile_Epilogue
NtDeviceIoControlFile_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtDeviceIoControlFile_Epilogue:
	mov r10, rcx
	syscall
	ret
NtDeviceIoControlFile ENDP

NtQueueApcThread PROC
	mov rax, gs:[60h]                          ; Load PEB into RAX.
NtQueueApcThread_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtQueueApcThread_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtQueueApcThread_Check_10_0_XXXX
	jmp NtQueueApcThread_SystemCall_Unknown
NtQueueApcThread_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtQueueApcThread_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueueApcThread_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtQueueApcThread_SystemCall_6_3_XXXX
	jmp NtQueueApcThread_SystemCall_Unknown
NtQueueApcThread_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtQueueApcThread_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtQueueApcThread_SystemCall_6_1_7601
	jmp NtQueueApcThread_SystemCall_Unknown
NtQueueApcThread_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtQueueApcThread_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtQueueApcThread_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtQueueApcThread_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtQueueApcThread_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtQueueApcThread_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtQueueApcThread_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtQueueApcThread_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtQueueApcThread_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtQueueApcThread_SystemCall_10_0_18363
	jmp NtQueueApcThread_SystemCall_Unknown
NtQueueApcThread_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0042h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0042h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0043h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 0044h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 0045h
	jmp NtQueueApcThread_Epilogue
NtQueueApcThread_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtQueueApcThread_Epilogue:
	mov r10, rcx
	syscall
	ret
NtQueueApcThread ENDP

NtWaitForMultipleObjects PROC
	mov rax, gs:[60h]                                  ; Load PEB into RAX.
NtWaitForMultipleObjects_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 6
	je  NtWaitForMultipleObjects_Check_6_X_XXXX
	cmp dword ptr [rax+118h], 10
	je  NtWaitForMultipleObjects_Check_10_0_XXXX
	jmp NtWaitForMultipleObjects_SystemCall_Unknown
NtWaitForMultipleObjects_Check_6_X_XXXX:               ; Check minor version for Windows Vista/7/8.
	cmp dword ptr [rax+11ch], 1
	je  NtWaitForMultipleObjects_Check_6_1_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtWaitForMultipleObjects_SystemCall_6_2_XXXX
	cmp dword ptr [rax+11ch], 2
	je  NtWaitForMultipleObjects_SystemCall_6_3_XXXX
	jmp NtWaitForMultipleObjects_SystemCall_Unknown
NtWaitForMultipleObjects_Check_6_1_XXXX:               ; Check build number for Windows 7.
	cmp dword ptr [rax+120h], 7600
	je  NtWaitForMultipleObjects_SystemCall_6_1_7600
	cmp dword ptr [rax+120h], 7601
	je  NtWaitForMultipleObjects_SystemCall_6_1_7601
	jmp NtWaitForMultipleObjects_SystemCall_Unknown
NtWaitForMultipleObjects_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp dword ptr [rax+120h], 10240
	je  NtWaitForMultipleObjects_SystemCall_10_0_10240
	cmp dword ptr [rax+120h], 10586
	je  NtWaitForMultipleObjects_SystemCall_10_0_10586
	cmp dword ptr [rax+120h], 14393
	je  NtWaitForMultipleObjects_SystemCall_10_0_14393
	cmp dword ptr [rax+120h], 15063
	je  NtWaitForMultipleObjects_SystemCall_10_0_15063
	cmp dword ptr [rax+120h], 16299
	je  NtWaitForMultipleObjects_SystemCall_10_0_16299
	cmp dword ptr [rax+120h], 17134
	je  NtWaitForMultipleObjects_SystemCall_10_0_17134
	cmp dword ptr [rax+120h], 17763
	je  NtWaitForMultipleObjects_SystemCall_10_0_17763
	cmp dword ptr [rax+120h], 18362
	je  NtWaitForMultipleObjects_SystemCall_10_0_18362
	cmp dword ptr [rax+120h], 18363
	je  NtWaitForMultipleObjects_SystemCall_10_0_18363
	jmp NtWaitForMultipleObjects_SystemCall_Unknown
NtWaitForMultipleObjects_SystemCall_6_1_7600:          ; Windows 7 SP0
	mov eax, 0058h
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_6_1_7601:          ; Windows 7 SP1 and Server 2008 R2 SP0
	mov eax, 0058h
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_6_2_XXXX:          ; Windows 8 and Server 2012
	mov eax, 0059h
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_6_3_XXXX:          ; Windows 8.1 and Server 2012 R2
	mov eax, 005ah
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 005bh
	jmp NtWaitForMultipleObjects_Epilogue
NtWaitForMultipleObjects_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtWaitForMultipleObjects_Epilogue:
	mov r10, rcx
	syscall
	ret
NtWaitForMultipleObjects ENDP

end