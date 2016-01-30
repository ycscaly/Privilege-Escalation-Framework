#pragma once
#include <Windows.h>
typedef struct Virtual_Address_x64 {

	UINT64 offset : 12,
		ptSelector : 9,
		pdSelector : 9,
		pdpSelector : 9,
		pml4Selector : 9,
		reservedCannonical: 16; //must be sign extended in reference to the first 48bits

} x64VirtualAddress, *Px64VirtualAddress;

//This struct represent the PTE for 4KB pages
typedef struct Page_Table_Entry_x64 {

	UINT64
		present : 1,
		writeable : 1,
		userPage : 1, //0 means supervisor, 1 means user mode page
		writethrough : 1,
		cacheDisable : 1,
		accessed : 1,
		dirty : 1,
		pat : 1,
		global : 1,
		: 3,
		phsyicalAddress : 40,
		: 7,
		protectionKey : 4,
		executeDisabled : 1;

} x64PageTableEntry, *Px64PageTableEntry;

