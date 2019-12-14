bits 32

; System V ABI: https://www.uclibc.org/docs/psABI-i386.pdf
; Scratch registers (callee can destroy them): eax, ecx, edx
; Callee-saved registers: ebx, ebp, esi, edi

compar:
push esi
push edi
; Now stack (leftmost is [esp]): <saved-edi> <saved-esi> <return-address> <a> <b>
; !! Which registers to save?
mov esi, [esp+12]  ; <a> pointer.
or edx, -1  ; Shorter than `mov ecx, -1'.
cmp [esi], dword -1
jne .1
neg edx
mov esi, [esp+16]  ; <b> pointer.
.1:
cmp [esi], dword 0
je .2
push edx
mov ecx, 10
sub esp, 40
mov edi, esp
lodsd  ; eax := <ab> -> f. (Function pointer.)
rep movsd
call eax
mov esp, edi
mov [esi+4-44], eax
pop eax  ; Result: -1 or 1, was in edx above.
;; Now stack (leftmost is [esp]): <saved-edi> <saved-esi> <return-address> <a> <b>
and [esi-44], dword 0  ; <ab> -> p = 0.
.2:
pop edi
pop esi
ret  ; Return value in eax.

align 16, nop

