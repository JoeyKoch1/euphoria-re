default rel

section .text

global eu_scan_byte_avx2

eu_scan_byte_avx2:
%ifidn __OUTPUT_FORMAT__, win64
    mov r9, rcx
    mov r10, rdx
    movzx r11d, r8b
%else
    mov r9, rdi
    mov r10, rsi
    movzx r11d, dl
%endif
    vmovd xmm0, r11d
    vpbroadcastb ymm0, xmm0
    xor eax, eax

.block:
    lea rcx, [rax + 32]
    cmp rcx, r10
    ja .tail
    vpcmpeqb ymm1, ymm0, [r9 + rax]
    vpmovmskb edx, ymm1
    test edx, edx
    jnz .found
    mov rax, rcx
    jmp .block

.found:
    bsf edx, edx
    add rax, rdx
    vzeroupper
    ret

.tail:
    vzeroupper

.byte:
    cmp rax, r10
    jae .done
    cmp byte [r9 + rax], r11b
    je .done
    inc rax
    jmp .byte

.done:
    ret

%ifidn __OUTPUT_FORMAT__, elf64
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
