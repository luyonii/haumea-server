; Remote injection stub (x86). Position-independent — only touches the arg
; struct and the mapped DLL inside the target process.
;
; stdcall: DWORD remote_stub(LPVOID args)
; arg layout:
;   [+0]  dll_base         (uint32)
;   [+4]  LoadLibraryA     (uint32, fn ptr)
;   [+8]  GetProcAddress   (uint32, fn ptr)
;   [+12] import_desc_rva  (uint32)
;   [+16] dllmain_rva      (uint32)
;   [+20] tls_cb_array_va  (uint32, absolute VA inside target; 0 if none)

.model flat
.code

PUBLIC _remote_stub@4
PUBLIC _remote_stub_end

_remote_stub@4 PROC
    push    ebp
    mov     ebp, esp
    sub     esp, 12
    push    ebx
    push    esi
    push    edi

    mov     esi, [ebp+8]            ; args
    mov     ebx, [esi+0]            ; dll_base
    mov     edi, [esi+12]           ; import_desc_rva
    test    edi, edi
    jz      lbl_after_imports
    add     edi, ebx                ; edi -> IMAGE_IMPORT_DESCRIPTOR

lbl_next_desc:
    mov     eax, [edi+12]           ; Name RVA
    test    eax, eax
    jz      lbl_after_imports
    add     eax, ebx
    push    eax
    call    DWORD PTR [esi+4]       ; LoadLibraryA(name)
    test    eax, eax
    jz      lbl_skip_desc
    mov     [ebp-4], eax            ; hmod

    mov     eax, [edi+0]            ; OriginalFirstThunk
    test    eax, eax
    jnz     lbl_ilt_ok
    mov     eax, [edi+16]           ; FirstThunk fallback
lbl_ilt_ok:
    add     eax, ebx
    mov     [ebp-12], eax           ; ilt ptr

    mov     eax, [edi+16]           ; FirstThunk (IAT)
    add     eax, ebx
    mov     [ebp-8], eax            ; iat ptr

lbl_next_thunk:
    mov     eax, [ebp-12]
    mov     eax, [eax]              ; thunk value
    test    eax, eax
    jz      lbl_skip_desc
    test    eax, 80000000h
    jnz     lbl_by_ord

    add     eax, ebx                ; IMAGE_IMPORT_BY_NAME ptr
    add     eax, 2                  ; skip Hint (WORD)
    push    eax
    push    DWORD PTR [ebp-4]
    call    DWORD PTR [esi+8]       ; GetProcAddress by name
    jmp     lbl_store

lbl_by_ord:
    and     eax, 0FFFFh
    push    eax
    push    DWORD PTR [ebp-4]
    call    DWORD PTR [esi+8]       ; GetProcAddress by ordinal

lbl_store:
    mov     edx, [ebp-8]
    mov     [edx], eax
    add     edx, 4
    mov     [ebp-8], edx
    mov     edx, [ebp-12]
    add     edx, 4
    mov     [ebp-12], edx
    jmp     lbl_next_thunk

lbl_skip_desc:
    add     edi, 20                 ; sizeof(IMAGE_IMPORT_DESCRIPTOR)
    jmp     lbl_next_desc

lbl_after_imports:
    mov     edi, [esi+20]           ; tls_cb_array_va (absolute)
    test    edi, edi
    jz      lbl_after_tls
lbl_next_tls:
    mov     eax, [edi]
    test    eax, eax
    jz      lbl_after_tls
    push    0
    push    1                       ; DLL_PROCESS_ATTACH
    push    ebx                     ; hModule
    call    eax
    add     edi, 4
    jmp     lbl_next_tls

lbl_after_tls:
    mov     eax, [esi+16]           ; dllmain_rva
    test    eax, eax
    jz      lbl_done
    add     eax, ebx
    push    0
    push    1
    push    ebx
    call    eax

lbl_done:
    pop     edi
    pop     esi
    pop     ebx
    mov     esp, ebp
    pop     ebp
    xor     eax, eax
    ret     4                       ; stdcall WINAPI thread proc

; End marker placed INSIDE the same PROC so the linker cannot reorder it away
; from the stub body. `&_remote_stub_end - &_remote_stub@4` == stub size in
; bytes (plus one trailing `ret` of the marker itself, which is benign).
_remote_stub_end LABEL BYTE
    ret
_remote_stub@4 ENDP

END
