   AREA     .text, CODE
                           
Trampoline_ASM_ARM64 FUNCTION

        EXPORT  Trampoline_ASM_ARM64 

NETIntro        ; .NET Barrier Intro Function
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0        
OldProc         ; Original Replaced Function
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0        
NewProc        ; Detour Function
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0        
NETOutro       ; .NET Barrier Outro Function
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0        
IsExecutedPtr  ; Count of times trampoline was executed
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0
        DCB 0        

        ;

start                           
        STP      X0, X1, [SP, #-0x20]

stop

        ENDFUNC
        END                     
