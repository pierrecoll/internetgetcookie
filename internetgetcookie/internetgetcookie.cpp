// internetgetcookie.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include "pch.h"
#include "stdio.h"
#include <Windows.h>
#include <WinInet.h>
#include <iepmapi.h>
#include <sddl.h>

#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"iepmapi.lib")

DWORD GetProcessIntegrityLevel();
DWORD ErrorPrint();
void CreateLowProcess();

void ShowUsage()
{	
	printf("INTERNETGETCOOKIE  version 1.7\r\n");
	printf("\r\n");
	printf("pierrelc@microsoft.com January 2021\r\n");
	printf("Usage: INTERNETGETCOOKIE accepts an URL as parameter and optionaly a cookie name.\r\n");
	printf("internetgetcookie url [cookiename]\r\n");
	printf("When cookiename is used, gives the option to delete the cookie (sets expiration date in the past)\r\n");
	printf("See https://docs.microsoft.com/en-us/windows/win32/wininet/managing-cookies\r\n");
	printf("and https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetgetcookieexa");
}

WCHAR* ExtractToken(LPTSTR lpszData)
{
	// Code to display the cookie data.
	//+		lpszData	0x010dee48 L"WebLanguagePreference=fr-fr; WT_NVR=0=/:1=web; SRCHUID=V=2&GUID=9087E76D5D4343F5BFE07F75D80435E4&dmnchg=1; SRCHD=AF=NOFORM; WT_FPC=id=2186e6812f80d94b48a1502956146257:lv=1502956146257:ss=1502956146257...	wchar_t *
	// Searching token separated by ";"

	WCHAR seps[] = L";";
	WCHAR* token = NULL;
	WCHAR* next_token = NULL;
	WCHAR* CookieName = NULL;

	//get the first token:
	token = wcstok_s(lpszData, seps, &next_token);

	// While there are token
	while (token != NULL)
	{
		// Get next token:
		if (token != NULL)
		{
			//wprintf(L" %s\n", token);
			unsigned int CookieLen = wcslen(token);
			unsigned int i;
			for (i = 0; i < CookieLen; i++)
			{
				if (*(token + i) == L'=')
				{
					*(token + i) = '\0';
					CookieName = token;
					//strip initial space if needed
					if (CookieName[0] == ' ')
					{
						CookieName += 1;
					}
					WCHAR* CookieValue = token + i + 1;
					wprintf(L"Cookie Name  = %s\r\n", CookieName);
					wprintf(L"Cookie Value = %s\r\n", CookieValue);
					break;
				}
			}
			token = wcstok_s(NULL, seps, &next_token);
		}
	}
	return CookieName;
}

WCHAR wszUrl[INTERNET_MAX_URL_LENGTH] = L"";
WCHAR wszCookieName[INTERNET_MAX_URL_LENGTH] = L"";

int main(int argc, char* argv[])
{
	if ((argc != 2) && (argc != 3))
	{
		ShowUsage();
		exit(0L);
	}

	MultiByteToWideChar(CP_ACP, 0, argv[1], strlen(argv[1]), wszUrl, INTERNET_MAX_URL_LENGTH);
	wszUrl[strlen(argv[1])] = 0;
	wprintf(L"Url : %s\r\n", wszUrl);

	if (argc == 2)
	{

		WCHAR szDecodedUrl[INTERNET_MAX_URL_LENGTH]=L"";
		DWORD cchDecodedUrl = INTERNET_MAX_URL_LENGTH;
		WCHAR szOut[INTERNET_MAX_URL_LENGTH]=L"";
	
		LPTSTR lpszData = NULL;   // buffer to hold the cookie data
		DWORD dwSize = 0;           // variable to get the buffer size needed
		BOOL bReturn;
		// Insert code to retrieve the URL.

retry:
		// The first call to InternetGetCookie will get the required
		// buffer size needed to download the cookie data.
		wprintf(L"Calling InternetGetCookie for url %s\r\n", wszUrl);
		bReturn = InternetGetCookie(wszUrl, NULL, lpszData, &dwSize);
		wprintf(L"InternetGetCookie returning %d dwSize = %d\r\n", bReturn, dwSize);
		if (bReturn == FALSE)
		{
			DWORD dwError = GetLastError();
			// Check for an insufficient buffer error.
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				// Allocate the necessary buffer.
				lpszData = new TCHAR[dwSize];
				wprintf(L"Allocating %d bytes and retrying.\r\n", dwSize);
				// Try the call again.
				goto retry;
			}
			else
			{
				// Error handling code.			
				if (dwError == ERROR_NO_MORE_ITEMS)
				{
					HRESULT hr = IEIsProtectedModeURL(wszUrl);
					if (SUCCEEDED(hr))
					{
						DWORD dwFlags = 0L;
						
						TCHAR szActualCookie[MAX_PATH];
						HRESULT hr = E_FAIL;
						DWORD dwSize = MAX_PATH;

						printf("This is a protected mode url so the tool needs to be run from a low or medium integrity process.\r\n");
						//IEGetProtectedModeCookie requires a cookie name? or can only be calld from ie!, 

						DWORD dwProcessIntegrityLevel;
						dwProcessIntegrityLevel = GetProcessIntegrityLevel();

						hr=IEGetProtectedModeCookie(wszUrl, NULL, szActualCookie, &dwSize,dwFlags);
						if (SUCCEEDED(hr))
						{
							printf("IEGetProtectedModeCookie OK\r\n");
							printf("Cookie Data: %S Size:%u Flags:%X\r\n", szActualCookie, dwSize, dwFlags);
							ExtractToken(szActualCookie);
						}
						else
						{
							DWORD dwError = GetLastError();
							printf("IEGetProtectedModeCookie KO: %X\r\n",dwError);  //getting 0x1f ERROR_GEN_FAILURE
							if (dwError == 0x1F)
							{
								printf("IEGetProtectedModeCookie may fail when called from an elevated command prompt\r\n");
							}
							if (dwProcessIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
							{
								printf("Starting low cannot be done from an administrative command prompt (High Integrity Level)\r\n");
								exit(-1L);
							}
							else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
							{
								//¨process already Low 
								printf("Process already running at low integrity\r\n");
							}
							else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
							{
								CreateLowProcess();
								exit(0L);
							}
							else
							{
								printf("Unexpected integity level for -low option\r\n");
							}
						}
					}
					else
					{						
						printf("There is no cookie for the specified URL and all its parents.\r\n");
						exit(1L);
					}
				}
				else
				{
					printf("InternetGetCookie failed with error %d.\r\n", dwError);
					exit(-1L);
				}
			}
		}
		else
		{
			printf("InternetGetCookie succeeded.\r\n");
			printf("Cookie data : %S\r\n\r\n", lpszData);
			if (lpszData)
			{
				
			}  
			else
			{
				// Allocate the necessary buffer.
				lpszData = new TCHAR[dwSize];
				// Try the call again.
				goto retry;
			}

			// Release the memory allocated for the buffer.
			delete[]lpszData;
		}

		lpszData = NULL;   // buffer to hold the cookie data
		dwSize = 0;           // variable to get the buffer size needed
		DWORD dwFlags = INTERNET_COOKIE_NON_SCRIPT;
	retryEx:
		// The first call to InternetGetCookieEx will get the required
		// buffer size needed to download the cookie data.
		wprintf(L"Calling InternetGetCookieEx for url %s with no cookie name and flag INTERNET_COOKIE_NON_SCRIPT.\r\n", wszUrl);
		bReturn = InternetGetCookieEx(wszUrl, NULL, lpszData, &dwSize,dwFlags,NULL);
		wprintf(L"InternetGetCookieEx returning %d dwSize = %d.\r\n", bReturn, dwSize);
		if (bReturn == FALSE)
		{
			DWORD dwError = GetLastError();
			// Check for an insufficient buffer error.
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				// Allocate the necessary buffer.
				lpszData = new TCHAR[dwSize];
				wprintf(L"No Cookie data (If NULL is passed to lpszCookieData, the call will succeed and the function will not set ERROR_INSUFFICIENT_BUFFER)\r\n");
				wprintf(L"Allocating %d bytes and retrying.\r\n", dwSize);
				// Try the call again.
				goto retryEx;
			}
			else
			{
				// Error handling code.			
				if (dwError == ERROR_NO_MORE_ITEMS)
				{
					printf("There is no cookie for the specified URL and all its parents.\r\n");
					exit(1L);
				}
				else
				{
					printf("InternetGetCookieEx failed with error %d.\r\n", dwError);
					exit(-1L);
				}
			}
		}
		else
		{
			printf("InternetGetCookieEx succeeded.\r\n");
			printf("Cookie data : %S\r\n\r\n", lpszData);
			if (lpszData)
			{
				ExtractToken(lpszData);
			}
			else
			{
				// Allocate the necessary buffer.
				lpszData = new TCHAR[dwSize];
				// Try the call again.
				goto retryEx;
			}

			// Release the memory allocated for the buffer.
			delete[]lpszData;
		}
	}
	if (argc == 3)
	{

		MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]), wszCookieName, INTERNET_MAX_URL_LENGTH);
		wszUrl[strlen(argv[1])] = 0;
		wprintf(L"Cookie Name : %s.\r\n", wszCookieName);
		BOOL bReturn;
		DWORD dwSize = 0;

		LPTSTR lpszCookieData = NULL;   // buffer to hold the cookie data
		DWORD dwFlags = 0L;

	retryEx2:
		wprintf(L"Calling InternetGetCookieEx for url %s and cookie name %s dwFlags: %X dwSize :%d\r\n", wszUrl, wszCookieName, dwFlags, dwSize);
		bReturn = InternetGetCookieEx(wszUrl, wszCookieName, lpszCookieData, &dwSize, dwFlags, NULL);
		wprintf(L"InternetGetCookieEx returning %d dwSize : %d\r\n", bReturn, dwSize);
		if (bReturn == TRUE)
		{
			wprintf(L"InternetGetCookieEx succeeded\r\n");
			if (lpszCookieData)
			{
				wprintf(L"Cookie data : %s.\r\n", lpszCookieData);

				printf("Type y if you want to delete the cookie or any other character to exit..........\r\n");
				printf("\r\n");
				char c;
				c = (char)getchar();
				if ((c == 'y') || (c == 'Y'))
				{
					getchar();  //to get cr
					printf("Deleting (calling InternetSetCookie with expiration date set to Sat,01-Jan-2000 00:00:00 GMT) for cookie:\r\n");
					WCHAR* CookieName = ExtractToken(lpszCookieData);
					bReturn = InternetSetCookie(wszUrl, CookieName,
						TEXT(";expires=Sat,01-Jan-2000 00:00:00 GMT"));
					if (bReturn == FALSE)
					{
						DWORD dwError = GetLastError();
						wprintf(L"InternetSetCookie failed with error : %d %X\r\n", dwError, dwError);
						if (dwError == ERROR_INVALID_OPERATION)
						{
							wprintf(L"ERROR_INVALID_OPERATION -> Calling InternetSetCookieEx with flag INTERNET_COOKIE_NON_SCRIPT\r\n");
							bReturn = InternetSetCookieEx(wszUrl, CookieName,
								TEXT(";expires=Sat,01-Jan-2000 00:00:00 GMT"), INTERNET_COOKIE_NON_SCRIPT, 0);
							if (bReturn == FALSE)
							{
								wprintf(L"InternetSetCookieEx failed with error : %d %X.\r\n", dwError, dwError);
							}
							else
							{
								wprintf(L"Calling InternetSetCookieEx to delete cookie %s succeeded.\r\n", CookieName);
							}
						}
					}
					else
					{
						wprintf(L"Calling InternetSetCookie to delete cookie %s succeeded.\r\n",CookieName);
					}
				}
			}
			else
			{
				wprintf(L"No Cookie data (If NULL is passed to lpszCookieData, the call will succeed and the function will not set ERROR_INSUFFICIENT_BUFFER)\r\n");
				wprintf(L"Allocating %d bytes and retrying.\r\n", dwSize);
				// Allocate the necessary buffer.
				lpszCookieData = new TCHAR[dwSize];
				// Try the call again.
				goto retryEx2;
			}
		}

		if (bReturn == FALSE)
		{
			DWORD dwError = GetLastError();
			wprintf(L"InternetGetCookieEx failed with error : %d %X\r\n", dwError, dwError);

			// Check for an insufficient buffer error.
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				wprintf(L"ERROR_INSUFFICIENT_BUFFER: allocating %d bytes and retrying\r\n", dwSize);
				// Allocate the necessary buffer.
				lpszCookieData = new TCHAR[dwSize];
				// Try the call again.
				goto retryEx2;
			}
			else if (dwError == ERROR_NO_MORE_ITEMS)
			{
				wprintf(L"ERROR_NO_MORE_ITEMS: No cookied data as specified could be retrieved\r\n");
				if (dwFlags == 0L)
				{
					wprintf(L"Re-trying with INTERNET_COOKIE_HTTPONLY flag\r\n");
					dwFlags = INTERNET_COOKIE_HTTPONLY;
					goto retryEx2;
				}
			}
			else if (dwError == ERROR_INVALID_PARAMETER)
			{
				wprintf(L"ERROR_INVALID_PARAMETER: either the pchURL or the pcchCookieData parameter is NULL.\r\n");
			}
			else
			{
				wprintf(L"Unexpected error\r\n");
			}
		}
	}

	return 0L;
}


//From https://msdn.microsoft.com/en-us/library/bb250462(VS.85).aspx(d=robot)
void CreateLowProcess()
{
	BOOL bRet;
	HANDLE hToken;
	HANDLE hNewToken;

	// Notepad is used as an example
	WCHAR wszProcessName[MAX_PATH];
	GetModuleFileNameW(NULL, wszProcessName, MAX_PATH - 1);
	WCHAR* lpwszCommandLine = GetCommandLineW();

	// Low integrity SID
	WCHAR wszIntegritySid[20] = L"S-1-16-4096";
	//WCHAR wszIntegritySid[129] = L"S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194-4256926629-1688279915-2739229046-3928706915";
	PSID pIntegritySid = NULL;

	TOKEN_MANDATORY_LABEL TIL = { 0 };
	PROCESS_INFORMATION ProcInfo = { 0 };
	STARTUPINFOW StartupInfo = { 0 };
	ULONG ExitCode = 0;

	if (OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
	{
		if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
			SecurityImpersonation, TokenPrimary, &hNewToken))
		{
			if (ConvertStringSidToSidW(wszIntegritySid, &pIntegritySid))
			{
				TIL.Label.Attributes = SE_GROUP_INTEGRITY;
				TIL.Label.Sid = pIntegritySid;

				// Set the process integrity level
				if (SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL,
					sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid)))
				{
					// Create the new process at Low integrity
					bRet = CreateProcessAsUserW(hNewToken, wszProcessName,
						lpwszCommandLine, NULL, NULL, FALSE,
						0, NULL, NULL, &StartupInfo, &ProcInfo);
					if (!bRet)
					{
						printf("CreateProcessAsUserW failed\r\n");
						ErrorPrint();
					}
					else
					{
						printf("CreateProcessAsUser %ws with Low Integrity. Command line: %ws\r\n", wszProcessName, lpwszCommandLine);
					}
				}
				else
				{
					printf("SetTokenInformation failed\r\n");
					ErrorPrint();
				}
				LocalFree(pIntegritySid);
			}
			else
			{
				printf("ConvertStringSidToSidW failed\r\n");
				ErrorPrint();
			}
			CloseHandle(hNewToken);
		}
		else
		{
			printf("DuplicateTokenEx failed\r\n");
			ErrorPrint();
		}
		CloseHandle(hToken);
	}
	else
	{
		printf("OpenProcessToken failed\r\n");
		ErrorPrint();
	}
}
DWORD GetProcessIntegrityLevel()
{
	HANDLE hToken;
	HANDLE hProcess;

	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel;

	hProcess = GetCurrentProcess();
	if (OpenProcessToken(hProcess, TOKEN_QUERY |
		TOKEN_QUERY_SOURCE, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel,
			NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,
					dwLengthNeeded);
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel,
						pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
							(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

						if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
						{
							// Low Integrity
							wprintf(L"Running as Low Integrity Process\r\n");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
							dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
						{
							// Medium Integrity
							wprintf(L"Running as Medium Integrity Process\r\n");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
						{
							// High Integrity
							wprintf(L"Running as High Integrity Process\r\n");
						}
						return dwIntegrityLevel;
					}
					else
					{
						printf("GetProcessIntegrityLevel: GetTokenInformation failed\r\n");
						ErrorPrint();
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
	}
	else
	{
		printf("GetProcessIntegrityLevel: OpenProcessToken failed\r\n");
		ErrorPrint();
	}
	return -1;
}

