; Położenie tego kodu zostanie ustawione na RVA pamięci, w której
; docelowo ma się on znaleźć (za pomocą dyrektywy ORG asemblera nasm).
__begin_marker: ; Etykieta używana przez nasz parser plików .map

%macro redirect 2 ; Argumenty: adres funkcji (RVA), indeks
	longjmp_%2:
		jmp %1 ; Skok do oryginalnej funkcji. Ponieważ jmp jest skokiem
		       ; względnym, nie musimy przejmować się, gdzie biblioteka
		       ; zostanie załadowana do pamięci (czyli znać docelowego VA)
	times 5 nop    ; umożliwia hot-patching
	align 16, nop  ; wyrównanie adresu wpisu do 16 bajtów
	entry_%2: ; Etykieta entry_<indeks> zostanie użyta jako
	          ; nowy adres funkcji o tym indeksie
		jmp short longjmp_%2 ; Pierwsza instrukcja musi zajmować
		                     ; przynajmniej 2 bajty (hot-patching
		                     ; tego wymaga)
	; Alternatywna wersja:
	;je %1
	;jne %1
%endmacro
