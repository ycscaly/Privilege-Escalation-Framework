#pragma once

#include <Windows.h>

/*
	Vulnerability Types follows
*/
typedef void(*WRITE_WHAT_WHERE_VULNERABILITY)(UINT64 what, UINT64 where);
typedef void(*INCREMENT_ARBITRARY_BYTE_VULNERABILITY)(UINT64 byteAddress);
typedef void(*KERNEL_CONTROL_PROGRAM_COUNTER_VULNERABILITY)(UINT64 newProgramCounter);


/*
	Vulnerability Implementation and exposure follows:
*/
extern WRITE_WHAT_WHERE_VULNERABILITY VulnerableDriverWriteWhatWhere;
extern INCREMENT_ARBITRARY_BYTE_VULNERABILITY VulnerableDriverIncrementArbitraryByte;
extern KERNEL_CONTROL_PROGRAM_COUNTER_VULNERABILITY VulnerableDriverControlProgramCounter;