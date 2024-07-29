.code

getPEB proc
    mov eax, gs:[60h]
    ret
getPEB endp

CheckDebugger proc
    xor eax, eax
    call getPEB
    movzx eax, byte ptr [eax+2h] ; PEB->BeingDebugged
    ret
CheckDebugger endp

end
