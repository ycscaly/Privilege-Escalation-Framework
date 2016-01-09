#pragma once

#include <Windows.h>

/*
	Vulnerability Types follows
*/
typedef void(*WRITE_WHAT_WHERE_VULNERABILITY)(UINT64 what, UINT64 where);
typedef void(*INCREMENT_ARBITRARY_BYTE_VULNERABILITY)(UINT64 byteAddress);



/*
	Vulnerability Implementation and exposure follows:
*/
extern WRITE_WHAT_WHERE_VULNERABILITY VulnerableDriverWriteWhatWhere;
extern INCREMENT_ARBITRARY_BYTE_VULNERABILITY VulnerableDriverIncrementArbitraryByte;