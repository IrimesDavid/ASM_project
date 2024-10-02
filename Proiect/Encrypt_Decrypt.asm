.386
.model flat, stdcall

includelib msvcrt.lib
extern printf: proc
extern scanf: proc
extern fscanf: proc
extern fprintf: proc
extern fopen: proc
extern fclose: proc
extern exit: proc
extern fread: near
extern fwrite: near
public start

.data
  mesaj_exit_program db "Introduceti '1'->exit sau '2'->repeat : ",0
  exit_program db 0
  exit_program_format db "%d",0
  
  mesaj_choice db "Introduceti '1' pt criptare si '2' pt decriptare: ",0
  choice db 0; '1'=encrypt ; '2'=decrypt 
  choice_format db "%d",0

  mesaj_start db "Introduceti calea spre fisier :",0
  nume_source db 100 dup(0) 
  nume_source_format db "%s", 0
  
  mesaj_key db "Introduceti cheia de criptare/decriptare : ",0
  key db 0
  key_format db "%d",0
  
  mesaj_operatie db "Introduceti operatia ('1'->alg1, '2'->alg2) : ",0
  operator_format db "%d",0
  operator db 0
  
  
  error_format db "Error!	", 0 
  ascii db 0 
  type_read db "r",0
  type_write db "r+", 0
  type_read_bin db "rb+",0 ; obs: putem folosi doar asta peste tot
  nume_destination db "sursa.txt",0
  fscanf_format db "%c",0 
  fprintf_format db "%c",0
  pointer_source dd 0
  pointer_destination dd 0
  array db 200 dup(0); 
  buffer db 10 DUP(0); 
  fscanf_10byte db "%s",0
  fprintf_byte db "%s",0
  pas dd 0
  sfarsitSource dd 0

.code

start:
    xor eax,eax
	
    ;Read choice
	push offset mesaj_choice
	call printf
	add esp,4
	push offset choice
	push offset choice_format
	call scanf
	add esp,8
	;vf daca choice e diferit de 1 si de 2
	cmp choice,1
	je continuare_choice
	cmp choice,2
	je continuare_choice
	jmp eroare
	
	continuare_choice:
    ; The path to the source file
    push offset mesaj_start
    call printf
    add esp,4
	
    ; Read the source file name
    push  offset nume_source
    push offset nume_source_format
    call scanf
    add esp,8
	
    ; open source file
    push offset type_read
    push offset nume_source
    call fopen
    add esp,8
    mov pointer_source,eax 

    ; test if the file exists 
    cmp pointer_source,0
    je eroare

    ; create the destination file 
    push offset type_write
    push offset nume_destination
    call fopen
    mov pointer_destination,eax 
    add esp,8
	
	;Read the operation
	push offset mesaj_operatie
	call printf
	add esp, 4
	push offset operator
	push offset operator_format
	call scanf
	add esp, 8
	;vf daca operator e diferit de 1 si de 2
	cmp operator,1
	je continuare_operation
	cmp operator,2
	je continuare_operation
	jmp eroare
	
	continuare_operation:
	;Read the encryption key
	push offset mesaj_key
	call printf
	add esp, 4
	push offset key
	push offset key_format
	call scanf
	add esp, 8
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	;luam adresa textului si citim pe rand caracter cu caracter
    lea esi,array   
    mov pas,esi 
    xor edi,edi
    mov edi,esi
    add edi,100; capacitate maxima a textului
	
	cmp choice,1
	je encryption
	cmp choice,2
	je decryption
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
encryption:

cmp operator,1
je e1
cmp operator,2
je e2

			e1:
				push offset ascii
				push offset fscanf_format
				push pointer_source
				call fscanf
				add esp,12
				mov sfarsitSource,eax
				cmp sfarsitSource,-1
				je afisare_bloc ; daca am ajuns la sfarsitul fisierului, iesim din bucla
				xor ebx,ebx
				mov bl,ascii                  
				not bl
				add bl,1
				xor ecx,ecx
				mov cl,key
				ror bl,cl
				mov [esi],ebx
				cmp esi,edi
				inc esi
				jb e1; cat timp esi mai mic ca edi, tot citim
			jmp afisare_bloc;se executa doar cand textul din fisier e prea lung si nu mai putem retine in array
;--------------------------------------------------------------------------------------------------------------------------------
			e2:
				xor ecx,ecx
				Lx10:
				inc ecx
				xor ebx,ebx
				push offset ascii
				push offset fscanf_format
				push pointer_source
				call fscanf
				add esp,12
				mov sfarsitSource,eax
				cmp sfarsitSource,-1
				je afisare_bloc
				
				mov bl,ascii
				not bl
				xor bl,key
				
				mov [esi],ebx
				inc esi
				
				cmp ecx,10
				je continua_e2
				jmp Lx10
			continua_e2:
				cmp esi,edi
				jb e2; cat timp esi mai mic ca edi, tot citim
			jmp afisare_bloc;se executa doar cand textul din fisier e prea lung si nu mai putem retine in array
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
decryption:

cmp operator,1
je d1
cmp operator,2
je d2

			d1:
				push offset ascii
				push offset fscanf_format
				push pointer_source
				call fscanf
				add esp,12
				mov sfarsitSource,eax
				cmp sfarsitSource,-1
				je afisare_bloc ; daca am ajuns la sfarsitul fisierului, iesim din bucla
				xor ebx,ebx
				mov bl,ascii   
				xor ecx,ecx
				mov cl,key
				rol bl,cl		
				sub bl,1
				not bl
				mov [esi],ebx
				cmp esi,edi
				inc esi
				jb d1; cat timp esi mai mic ca edi, tot citim
			jmp afisare_bloc;se executa doar cand textul din fisier e prea lung si nu mai putem retine in array
;---------------------------------------------------------------------------------------------------------------------------------
			d2:
				xor ecx,ecx
				Ly10:
				inc ecx
				xor ebx,ebx
				push offset ascii
				push offset fscanf_format
				push pointer_source
				call fscanf
				add esp,12
				mov sfarsitSource,eax
				cmp sfarsitSource,-1
				je afisare_bloc
				
				mov bl,ascii
				not bl
				xor bl,key
				
				mov [esi],ebx
				inc esi
				
				cmp ecx,10
				je continua_d2
				jmp Ly10
			continua_d2:
				cmp esi,edi
				jb d2; cat timp esi mai mic ca edi, tot citim
			jmp afisare_bloc;se executa doar cand textul din fisier e prea lung si nu mai putem retine in array
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;afisam
	afisare_bloc:
	mov pas,esi
	sub pas,1; adauga un caracter aiurea fara asta
    xor esi,esi
    lea esi, array
    dec esi
    afisare_caracter:
		inc esi
        xor edx,edx
        mov dl,[esi]
		
        push edx
        push offset fprintf_format
        push pointer_destination
        call fprintf
        add esp,12
		
        cmp esi,pas
        jne afisare_caracter
	
		jmp continua
fin :
         push 0
         call exit

continua:
		  push pointer_source
          call fclose
          add esp,4
          push pointer_destination
          call fclose
          add esp,4
          ;jmp fin
		  
		exit_or_not:
		push offset mesaj_exit_program
		call printf
		add esp,4
		push offset exit_program
		push offset exit_program_format
		call scanf
		add esp,8
		cmp exit_program,2
		je start
		cmp exit_program,1
		je fin
		jmp eroare
          
eroare: push offset error_format
        call printf
        jmp fin
end start
