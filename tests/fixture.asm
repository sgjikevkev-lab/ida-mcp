OPTION CASEMAP:NONE
EXTERN mcp_fixture_global:DWORD

PUBLIC mcp_fixture_partial_register
PUBLIC mcp_fixture_zero_extend
PUBLIC mcp_fixture_stack_alias
PUBLIC mcp_fixture_call_preserved
PUBLIC mcp_fixture_call_volatile
PUBLIC mcp_fixture_call_target
PUBLIC mcp_fixture_rsp_alias
PUBLIC mcp_fixture_flag_slice
PUBLIC mcp_fixture_global_alias
PUBLIC mcp_fixture_stack_partial_overwrite
PUBLIC mcp_fixture_high_byte_register

.code

mcp_fixture_partial_register PROC
    mov rax, 1122334455667788h
    mov al, 1
    mov rbx, rax
    ret
mcp_fixture_partial_register ENDP

mcp_fixture_zero_extend PROC
    mov rax, 1122334455667788h
    mov eax, 1
    mov rbx, rax
    ret
mcp_fixture_zero_extend ENDP

mcp_fixture_high_byte_register PROC
    mov rax, 1122334455667788h
    mov ah, 1
    mov rbx, rax
    ret
mcp_fixture_high_byte_register ENDP

mcp_fixture_stack_alias PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    mov qword ptr [rbp-8], rcx
    mov eax, dword ptr [rbp-4]
    add rsp, 20h
    pop rbp
    ret
mcp_fixture_stack_alias ENDP

mcp_fixture_rsp_alias PROC
    sub rsp, 28h
    mov qword ptr [rsp+20h], rcx
    mov eax, dword ptr [rsp+20h]
    add rsp, 28h
    ret
mcp_fixture_rsp_alias ENDP

mcp_fixture_flag_slice PROC
    stc
    jz mcp_fixture_flag_done
    nop
mcp_fixture_flag_done:
    ret
mcp_fixture_flag_slice ENDP

mcp_fixture_global_alias PROC
    mov dword ptr [mcp_fixture_global], ecx
    mov eax, dword ptr [mcp_fixture_global]
    ret
mcp_fixture_global_alias ENDP

mcp_fixture_stack_partial_overwrite PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    mov qword ptr [rbp-8], rcx
    mov byte ptr [rbp-8], 1
    mov rax, qword ptr [rbp-8]
    add rsp, 20h
    pop rbp
    ret
mcp_fixture_stack_partial_overwrite ENDP

mcp_fixture_call_preserved PROC
    mov rbx, rcx
    call mcp_fixture_call_target
    mov rax, rbx
    ret
mcp_fixture_call_preserved ENDP

mcp_fixture_call_volatile PROC
    mov rax, rcx
    call mcp_fixture_call_target
    mov rbx, rax
    ret
mcp_fixture_call_volatile ENDP

mcp_fixture_call_target PROC
    ret
mcp_fixture_call_target ENDP

END
