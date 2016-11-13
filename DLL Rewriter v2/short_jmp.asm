; Placement of this code will be set to RVA (not VA!) of destination memory
; (using ORG directive).
__begin_marker: ; Used by our .map parser

%macro redirect 2 ; Args: func address (RVA), func index
	longjmp_%2:
		jmp %1 ; Jump to original function. 'jmp' is relative so we don't
		       ; have to know target VA (relative distance is enough).
	times 5 nop    ; Allows hot-patching.
	align 16, nop  ; Alignment to 16
	entry_%2: ; entry_<index> label will be pointed by an exported symbol with this index
		jmp short longjmp_%2 ; First instruction must be at least 2-bytes long
		                     ; for hot-patching support.
	; Alternative version:
	;je %1
	;jne %1
%endmacro
