        area     .text, code, thumb, readonly

Trampoline_ASM_ARM FUNCTION

        export  Trampoline_ASM_ARM 
        export  Trampoline_ASM_ARM_DATA
        export  Trampoline_ASM_ARM_CODE

NETIntro       ; .NET Barrier Intro Function
        dcb 0
        dcb 0
        dcb 0
        dcb 0
OldProc        ; Original Replaced Function
        dcb 0
        dcb 0
        dcb 0
        dcb 0
NewProc        ; Detour Function
        dcb 0
        dcb 0
        dcb 0
        dcb 0
NETOutro       ; .NET Barrier Outro Function
        dcb 0
        dcb 0
        dcb 0
        dcb 0
IsExecutedPtr  ; Count of times trampoline was executed
        dcb 0
        dcb 0
        dcb 0
        dcb 0

Trampoline_ASM_ARM_CODE
start     
        push    {r0, r1, r2, r3, r4, lr}
        push    {r5-r10}
        vpush   {d0-d7}
        ldr     r5, IsExecutedPtr
        dmb     ish
try_inc_lock
        ldrex   r0, [r5]
        add     r0, r0, #1
        strex   r1, r0, [r5]
        cmp     r1, #0
        bne     try_inc_lock
        dmb     ish
        ldr     r2, NewProc
        cmp     r2, #0
        bne     call_net_entry
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call original method
        dmb     ish
try_dec_lock
        ldrex   r0, [r5]
        add     r0, r0, #-1
        strex   r1, r0, [r5]
        cmp     r1, #0
        bne     try_dec_lock
        dmb     ish

        ldr     r5, OldProc
        b       trampoline_exit
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method...
call_net_entry  ; call NET intro

        adr     r0, start ; Hook handle (only a position hint)
        add     r2, sp, #0x6C ; original sp (address of return address)
        ldr     r1, [sp, #0x6C] ; return address (value stored in original sp)
        ldr     r4, NETIntro
        blx     r4 ; Hook->NETIntro(Hook, RetAddr, InitialSP);
; should call original method?
        cmp     r0, #0
        bne     call_hook_handler

; call original method
        ldr     r5, IsExecutedPtr
        dmb     ish
try_dec_lock2        
        ldrex   r0, [r5]
        add     r0, r0, #-1
        strex   r1, r0, [r5]
        cmp     r1, #0
        bne     try_dec_lock2
        dmb     ish

        ldr     r5, OldProc
        b       trampoline_exit

call_hook_handler
        ldr     r5, NewProc
        adr     r4, call_net_outro ; adjust return address
        orr     r4, r4, 1 ; set PC bit 0 (Thumb state flag) for thumb mode address
        str     r4, [sp, #0x6C] ; store outro return to stack after hook handler is called
        b       trampoline_exit
 ; this is where the handler returns...
call_net_outro
        mov     r5, #0
        push    {r0, r1, r2, r3, r4, r5} ; save return handler
        add     r1, sp, #5*4
        adr     r0, start ; get address of next Hook struct pointer
        ; Param 2: Address of return address
        ldr     r5, NETOutro
        blx     r5       ; Hook->NETOutro(Hook, InAddrOfRetAddr);

        ldr     r5, IsExecutedPtr
        dmb     ish
try_dec_lock3
        ldrex   r0, [r5]
        add     r0, r0, #-1
        strex   r1, r0, [r5]
        cmp     r1, #0
        bne     try_dec_lock3
        dmb     ish

        pop     {r0, r1, r2, r3, r4, lr} ; restore return value of user handler...
; finally return to saved return address - the caller of this trampoline...
        bx      lr

trampoline_exit
        mov     r12, r5
        vpop    {d0-d7}
        pop     {r5-r10}
        pop     {r0, r1, r2, r3, r4, lr}
        
        bx      r12 ; mov     pc, r12

; outro signature, to automatically determine code size
Trampoline_ASM_ARM_DATA
        dcb     0x78
        dcb     0x56
        dcb     0x34
        dcb     0x12
      
        endfunc

        end
