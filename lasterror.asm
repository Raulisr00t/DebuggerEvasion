.code 

getTEB proc
	mov rax,qword ptr gs:[30h]
	ret
getTEB endp

CustomError proc
	xor eax,eax
	call getTEB
	mov eax,dword ptr [rax+68h] ;LastError Value
	ret
CustomError endp
end
