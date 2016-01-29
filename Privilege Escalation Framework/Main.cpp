#include "Vulnerabilities.h"
#include <stdio.h>
int main() {

	int test = 0;
	
	VulnerableDriverWriteWhatWhere((UINT64)5, (UINT64)&test);
	printf("Vulnerable Driver Write What Where vulnerbility trigger was %s\n", test == 5 ? "succefull" : "pure failure");
	
	test = 0;
	VulnerableDriverIncrementArbitraryByte((UINT64)&test);
	printf("Vulnerable Driver Increment Arbitrary Byte vulnerbility trigger was %s\n", test == 1 ? "succefull" : "pure failure");
	
	return 0;
}