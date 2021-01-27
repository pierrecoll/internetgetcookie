// internetgetcookie.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include "pch.h"
#include "stdio.h"
#include <Windows.h>
#include <WinInet.h>
#include <iepmapi.h>
#include <sddl.h>
#include "time.h"

#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"iepmapi.lib")

DWORD GetProcessIntegrityLevel();
DWORD ErrorPrint();
void CreateLowProcess();
WCHAR* ExtractSingleCookieToken(LPTSTR lpszData);
UINT16 ExtractCookiesToken(WCHAR* wszUrl, LPTSTR lpszData, BOOL bDisplay);
void FindCookies(WCHAR* wszUrl);
void FindCookie(WCHAR* wszUrl, WCHAR* wszCookieName);
BOOL DeleteCookie(WCHAR* wszUrl, WCHAR* wszCookieName);
void DumpCookie(WCHAR* wszUrl, WCHAR* wszCookieName);

BOOL bProtectedModeUrl = FALSE;
DWORD dwProcessIntegrityLevel = 0;

void ShowUsage()
{
	printf("INTERNETGETCOOKIE  version 1.9\r\n");
	printf("\r\n");
	printf("pierrelc@microsoft.com January 2021\r\n");
	printf("Usage: INTERNETGETCOOKIE accepts an URL as parameter and optionaly a cookie name.\r\n");
	printf("internetgetcookie url [cookiename]\r\n");
	printf("When cookiename is used, gives the option to delete the cookie (sets expiration date in the past)\r\n");
	printf("See https://docs.microsoft.com/en-us/windows/win32/wininet/managing-cookies\r\n");
	printf("and https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetgetcookieexa");
}

int main(int argc, char* argv[])
{

	if ((argc != 2) && (argc != 3) && (argc != 4))
	{
		ShowUsage();
		exit(0L);
	}
	if (argc == 2)
	{
		goto ParamParsed;
	}

ParamParsed:

	WCHAR wszUrl[INTERNET_MAX_URL_LENGTH] = L"";
	WCHAR wszCookieName[INTERNET_MAX_URL_LENGTH] = L"";

	dwProcessIntegrityLevel = GetProcessIntegrityLevel();


	MultiByteToWideChar(CP_ACP, 0, argv[1], strlen(argv[1]), wszUrl, INTERNET_MAX_URL_LENGTH);
	wszUrl[strlen(argv[1])] = 0;
	wprintf(L"Url : %s\r\n", wszUrl);
	
	//checking protocol of the url.Must be http or https
	int ch = ':';
	char* pdest;
	char protocol[6] = "";
	int result;

	// Search forward.
	pdest = strchr(argv[1], ch);
	result = (int)(pdest - argv[1] + 1);
	if (pdest != NULL)
	{
		if (result > 6)
		{
			printf("The protocol for the url must be http or https\r\n");
			exit(-1L);
		}
		lstrcpynA(protocol, argv[1], result);
		protocol[result - 1] = '\0';
		printf("Protocol of the url is: %s\r\n", protocol);
		if ((strncmp(protocol, "http", result - 1) != 0) && (strncmp(protocol, "https", result - 1) != 0))
		{
			printf("The protocol for the url must be http or https\r\n");
			exit(-1L);
		}
	}
	else
	{
		printf("The protocol for the url must be http or https\r\n");
		exit(-1L);
	}

	wprintf(L"Calling IEIsProtectedModeURL for url : %s\r\n", wszUrl);
	HRESULT hr = IEIsProtectedModeURL(wszUrl);
	if (hr == S_OK)
	{
		bProtectedModeUrl = TRUE;
		printf("Url would open in a protected mode process.\r\n");
	}
	else if (hr == S_FALSE)
	{
		printf("Url would not open in a protected mode process.\r\n");
	}
	else
	{
		printf("IEIsProtectedModeURL returning : %X\r\n", hr);
	}
	 
	if (argc == 2)
	{
		FindCookies(wszUrl);
	}
	if (argc == 3)
	{
		MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]), wszCookieName, INTERNET_MAX_URL_LENGTH);
		wszUrl[strlen(argv[1])] = 0;
		wprintf(L"Cookie Name : %s.\r\n", wszCookieName);
		FindCookie(wszUrl, wszCookieName);
	}

	return 0L;
}


void DumpCookie(WCHAR* wszUrl, WCHAR* wszCookieName)
{
	DWORD dwReturn = 0;

	LPTSTR lpszCookieData = NULL;   // buffer to hold the cookie data
	DWORD dwFlags = 0L;
	DWORD dwCookieCount = 0;
	INTERNET_COOKIE2 *pInternetCookie;
retryIC2:
	wprintf(L"Calling InternetGetCookieEx2 for url %s and cookie name %s dwFlags: %X\r\n", wszUrl, wszCookieName, dwFlags);
	dwReturn = InternetGetCookieEx2(wszUrl, wszCookieName, dwFlags, &pInternetCookie, &dwCookieCount);
	wprintf(L"InternetGetCookieEx2 returning %d Cookie Count : %d\r\n", dwReturn, dwCookieCount);
	if (dwReturn == ERROR_SUCCESS)
	{
		wprintf(L"InternetGetCookieEx2 succeeded\r\n");
		goto dumpcookie;
	}
	else
	{
		//call with flag INTERNET_COOKIE_NON_SCRIPT
		wprintf(L"Calling InternetGetCookieEx2 for url %s and cookie name %s dwFlags: %X = INTERNET_COOKIE_NON_SCRIPT\r\n", wszUrl, wszCookieName, dwFlags);
		dwReturn = InternetGetCookieEx2(wszUrl, wszCookieName, dwFlags, &pInternetCookie, &dwCookieCount);
		wprintf(L"InternetGetCookieEx returning %d Cookie count : %d\r\n", dwReturn, dwCookieCount);
		if (dwReturn == ERROR_SUCCESS)
		{
			wprintf(L"InternetGetCookieEx2 succeeded\r\n");
			goto dumpcookie;
		}
		else
		{
			wprintf(L"InternetGetCookieEx2 failed\r\n");
			return;
		}
	}
dumpcookie:
	if (dwCookieCount != 0)
	{
		wprintf(L"\tCookie name : %s\r\n", pInternetCookie->pwszName);
		wprintf(L"\tCookie value : %s\r\n", pInternetCookie->pwszValue);
		wprintf(L"\tCookie domain:  %s\r\n", pInternetCookie->pwszDomain);
		wprintf(L"\tCookie path : %s\r\n", pInternetCookie->pwszPath);
		wprintf(L"\tCookie flags : %X\r\n", pInternetCookie->dwFlags);

		if (pInternetCookie->dwFlags & INTERNET_COOKIE_IS_SECURE)
		{
			printf("\t\tThis is a secure cookie.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_IS_SESSION)
		{
			printf("\t\tThis is a session cookie.r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_IS_RESTRICTED)
		{
			printf("\t\tThis cookie is restricted to first - party contexts.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_HTTPONLY)
		{
			printf("\t\tThis is an HTTP - only cookie.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_HOST_ONLY )
		{
			printf("\t\tThis is a host - only cookie.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_HOST_ONLY_APPLIED)
		{
			printf("\t\tThe host - only setting has been applied to this cookie.\r\n");
		}		
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_SAME_SITE_STRICT)
		{
			printf("\t\tThe SameSite security level for this cookie is \"strict\"\r\n");
		}
		if (pInternetCookie->dwFlags & INTERNET_COOKIE_SAME_SITE_LAX)
		{
			printf("\t\tThe SameSite security level for this cookie is \"lax\"\r\n");
		}
								
		wprintf(L"\tExpiry time set : %S\r\n", pInternetCookie->fExpiresSet ? "true" : "false");

		TIME_ZONE_INFORMATION tzi;
		GetTimeZoneInformation(&tzi);

		SYSTEMTIME st, stLocal;
		BOOL bRV = FileTimeToSystemTime(&pInternetCookie->ftExpires, &st);
		SystemTimeToTzSpecificLocalTime(&tzi, &st, &stLocal);
		WCHAR szBuf[256];
		GetDateFormat(LOCALE_USER_DEFAULT, DATE_LONGDATE, &stLocal, NULL, szBuf, sizeof(szBuf));

		int iBufUsed = wcslen(szBuf);
		if (iBufUsed < sizeof(szBuf) - 2)
			szBuf[iBufUsed++] = ' ';
		GetTimeFormat(LOCALE_USER_DEFAULT, 0, &stLocal,
			NULL, szBuf + iBufUsed, sizeof(szBuf) - iBufUsed);
		char OEMTime[256];
		CharToOemBuff(szBuf, (LPSTR)OEMTime, wcslen(szBuf));
		OEMTime[wcslen(szBuf)] = '\0';

		wprintf(L"Expiry time : %S\r\n", OEMTime);
	}
	else
	{
		printf("dwCookiecount is NULL\r\n");
		if (dwProcessIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
		{
			printf("Starting low cannot be done from an administrative command prompt (High Integrity Level)\r\n");
			exit(-1L);
		}
		else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
		{

			if (dwFlags == 0)
			{
				dwFlags = INTERNET_COOKIE_NON_SCRIPT;
				goto retryIC2;
			}
			else
			{
				//¨process already Low 
				printf("Process already running at low integrity\r\n");
				exit(-2L);
			}
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

void FindCookie(WCHAR* wszUrl, WCHAR* wszCookieName)
{

	BOOL bReturn;
	DWORD dwSize = 0;

	LPTSTR lpszCookieData = NULL;   // buffer to hold the cookie data
	DWORD dwFlags = 0L;

retryEx:
	wprintf(L"Calling InternetGetCookieEx for url %s and cookie name %s dwFlags: %X dwSize :%d\r\n", wszUrl, wszCookieName, dwFlags, dwSize);
	bReturn = InternetGetCookieEx(wszUrl, wszCookieName, lpszCookieData, &dwSize, dwFlags, NULL);
	wprintf(L"InternetGetCookieEx returning %d dwSize : %d\r\n", bReturn, dwSize);
	if (bReturn == TRUE)
	{
		wprintf(L"InternetGetCookieEx succeeded\r\n");
		if (lpszCookieData)
		{
			wprintf(L"Cookie data : %s.\r\n", lpszCookieData);
			WCHAR* wszCookieName = ExtractSingleCookieToken(lpszCookieData);
			DumpCookie(wszUrl, wszCookieName);
			DeleteCookie(wszUrl, wszCookieName);
		}
		else
		{
			wprintf(L"No Cookie data (If NULL is passed to lpszCookieData, the call will succeed and the function will not set ERROR_INSUFFICIENT_BUFFER)\r\n");
			wprintf(L"Allocating %d bytes and retrying.\r\n", dwSize);
			// Allocate the necessary buffer.
			lpszCookieData = new TCHAR[dwSize];
			// Try the call again.
			goto retryEx;
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
			goto retryEx;
		}
		else if (dwError == ERROR_NO_MORE_ITEMS)
		{
			wprintf(L"ERROR_NO_MORE_ITEMS: No cookied data as specified could be retrieved\r\n");
			if (dwFlags == 0L)
			{
				wprintf(L"Re-trying with INTERNET_COOKIE_HTTPONLY flag\r\n");
				dwFlags = INTERNET_COOKIE_HTTPONLY;
				goto retryEx;
			}

			DWORD dwFlags = 0L;
			WCHAR szCookieData[MAX_PATH] = L"";
			HRESULT hr = E_FAIL;
			DWORD dwSize = MAX_PATH;

			printf("Protected mode url : calling IEGetProtectedModeCookie with dwFlags set to zero\r\n");
			hr = IEGetProtectedModeCookie(wszUrl, wszCookieName, szCookieData, &dwSize, dwFlags);
			if (SUCCEEDED(hr))
			{
				printf("IEGetProtectedModeCookie OK\r\n");
				printf("Cookie Data: %S Size:%u Flags:%X\r\n", szCookieData, dwSize, dwFlags);
				WCHAR* wszCookieName= ExtractSingleCookieToken(szCookieData);
				DumpCookie(wszUrl, wszCookieName);
				DeleteCookie(wszUrl, wszCookieName);
			}
			else
			{
				DWORD dwError = GetLastError();
				printf("IEGetProtectedModeCookie returning error: %X\r\n", dwError);  //getting 0x1f ERROR_GEN_FAILURE
				printf("Trying to restart the process with Low Integrity Level\r\n");
				if (dwProcessIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
				{
					printf("Starting low cannot be done from an administrative command prompt (High Integrity Level)\r\n");
					exit(-1L);
				}
				else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
				{
					//¨process already Low 
					printf("Process already running at low integrity\r\n");
					exit(-2L);
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

BOOL DeleteCookie(WCHAR* wszUrl, WCHAR* wszCookieName)
{
	wprintf(L"Type y if you want to delete  cookie %s for url %s or any other character to exit..........\r\n",wszCookieName,wszUrl);
	printf("\r\n");
	char c;
	c = (char)getchar();
	if ((c == 'y') || (c == 'Y'))
	{
		getchar();  //to get cr

		//cookie value does not matter
		BOOL bReturn = FALSE;
		wprintf(L"Deleting  cookie %s for url :%s by calling InternetSetCookie with expiration date set to Sat,01-Jan-2000 00:00:00 GMT\r\n", wszCookieName,wszUrl);
		bReturn = InternetSetCookieW(wszUrl, wszCookieName, L"Deleted;expires=Sat,01-Jan-2000 00:00:00 GMT");
		if (bReturn == FALSE)
		{
			DWORD dwError = GetLastError();
			wprintf(L"InternetSetCookie failed with error : %d %X\r\n", dwError, dwError);
			if (dwError == ERROR_INVALID_OPERATION)
			{
				wprintf(L"ERROR_INVALID_OPERATION -> Calling InternetSetCookieEx with flag INTERNET_COOKIE_NON_SCRIPT\r\n");
				bReturn = InternetSetCookieEx(wszUrl, wszCookieName,
					TEXT("Deleted;expires=Sat,01-Jan-2000 00:00:00 GMT"), INTERNET_COOKIE_NON_SCRIPT, 0);
				if (bReturn == FALSE)
				{
					dwError = GetLastError();
					wprintf(L"InternetSetCookieEx failed with error : %d %X.\r\n", dwError, dwError);
				}
				else
				{
					wprintf(L"Calling InternetSetCookieEx to delete cookie %s succeeded.\r\n", wszCookieName);
					return TRUE;
				}
			}
		}
		else
		{
			wprintf(L"Calling InternetSetCookie to delete cookie %s succeeded.\r\n", wszCookieName);
			return TRUE;
		}

		if (bProtectedModeUrl)
		{
			HRESULT hr = S_FALSE;
			wprintf(L"Deleting cookie %s by calling IESetProtectedModeCookie with expiration date set to Sat,01-Jan-2000 00:00:00 GMT\r\n", wszCookieName);
			hr = IESetProtectedModeCookie(wszUrl, wszCookieName, TEXT("Deleted;expires=Sat,01-Jan-2000 00:00:00 GMT"),0L);
			if (FAILED(hr))
			{
				wprintf(L"IESetProtectedModeCookie failed with error : %X\r\n", hr);
				wprintf(L"Calling IESetProtectedModeCookie with flag INTERNET_COOKIE_NON_SCRIPT\r\n");
				hr = IESetProtectedModeCookie(wszUrl, wszCookieName,
					TEXT("Deleted;expires=Sat,01-Jan-2000 00:00:00 GMT"), INTERNET_COOKIE_NON_SCRIPT);
				if (FAILED(hr))
				{
					wprintf(L"IESetProtectedModeCookie failed with error : %X.\r\n", hr);
					return FALSE;
				}
				else
				{
					wprintf(L"Calling IESetProtectedModeCookie to delete cookie %s succeeded.\r\n", wszCookieName);
					return TRUE;
				}				
			}
			else
			{
				wprintf(L"Calling IESetProtectedModeCookie to delete cookie %s succeeded.\r\n", wszCookieName);
				return TRUE;
			}
		}
	}
	return FALSE;
}

void FindCookies(WCHAR *wszUrl)
{
	printf("No cookie name given\r\n");
	printf("\r\n");
	WCHAR szDecodedUrl[INTERNET_MAX_URL_LENGTH] = L"";
	DWORD cchDecodedUrl = INTERNET_MAX_URL_LENGTH;
	WCHAR szOut[INTERNET_MAX_URL_LENGTH] = L"";

	LPTSTR lpszData = NULL;   // buffer to hold the cookie data
	DWORD dwSize = 0;           // variable to get the buffer size needed
	BOOL bReturn;
	UINT16 nbCookies = 0;
	UINT16 nbCookiesEx = 0;
	// Insert code to retrieve the URL.

retry:
	// The first call to InternetGetCookie will get the required
	// buffer size needed to download the cookie data.
	wprintf(L"Calling InternetGetCookie for url %s with dwSize: %d\r\n", wszUrl, dwSize);
	bReturn = InternetGetCookie(wszUrl, NULL, lpszData, &dwSize);
	wprintf(L"InternetGetCookie returning %d dwSize = %d\r\n", bReturn, dwSize);
	if (bReturn == FALSE)
	{
		DWORD dwError = GetLastError();
		wprintf(L"InternetGetCookie returning FALSE dwSize = %d error: %X\r\n", dwSize, dwError);
		// Check for an insufficient buffer error.
		if (dwError == ERROR_INSUFFICIENT_BUFFER)
		{
			// Allocate the necessary buffer.
			lpszData = new TCHAR[dwSize];
			wprintf(L"ERROR_INSUFFICIENT_BUFFER: Allocating %d bytes and retrying.\r\n", dwSize);
			// Try the call again.
			goto retry;
		}
		else
		{
			// Error handling code.			
			if (dwError == ERROR_NO_MORE_ITEMS)
			{
				printf("InternetGetCookie returning ERROR_NO_MORE_ITEMS\r\n");
				if (bProtectedModeUrl == TRUE)
				{
					DWORD dwFlags = 0L;
					WCHAR szCookieData[MAX_PATH] = L"";
					HRESULT hr = E_FAIL;
					DWORD dwSize = MAX_PATH;

					printf("Protected mode url : calling IEGetProtectedModeCookie with dwFlags set to zero\r\n");
					hr = IEGetProtectedModeCookie(wszUrl, NULL, szCookieData, &dwSize, dwFlags);
					if (SUCCEEDED(hr))
					{
						printf("IEGetProtectedModeCookie OK\r\n");
						printf("Cookie Data: %S Size:%u Flags:%X\r\n", szCookieData, dwSize, dwFlags);
						nbCookies = ExtractCookiesToken(wszUrl,szCookieData, TRUE);
					}
					else
					{
						DWORD dwError = GetLastError();
						printf("IEGetProtectedModeCookie returning error: %X\r\n", dwError);  //getting 0x1f ERROR_GEN_FAILURE
						printf("Trying to restart the process with Low Integrity Level\r\n");
						if (dwProcessIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
						{
							printf("Starting low cannot be done from an administrative command prompt (High Integrity Level)\r\n");
							exit(-1L);
						}
						else if (dwProcessIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
						{
							//¨process already Low 
							printf("Process already running at low integrity\r\n");
							exit(-2L);
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
					printf("No cookie found for the specified URL\r\n");
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
		if (lpszData)
		{
			nbCookies = ExtractCookiesToken(wszUrl,lpszData,TRUE);
		}
		else
		{
			wprintf(L"No Cookie data: Allocating %d bytes and retrying.\r\n", dwSize);
			// Allocate the necessary buffer.
			lpszData = new TCHAR[dwSize];
			// Try the call again.
			goto retry;
		}

		// Release the memory allocated for the buffer.
		delete[]lpszData;
	}

	printf("Searching for cookies with HttpOnly flag\r\n");
	lpszData = NULL;   // buffer to hold the cookie data
	dwSize = 0;           // variable to get the buffer size needed
	DWORD dwFlags = INTERNET_COOKIE_NON_SCRIPT;
retryEx:
	// The first call to InternetGetCookieEx will get the required
	// buffer size needed to download the cookie data.
	wprintf(L"Calling InternetGetCookieEx for url %s with no cookie name and flag INTERNET_COOKIE_NON_SCRIPT.\r\n", wszUrl);
	bReturn = InternetGetCookieEx(wszUrl, NULL, lpszData, &dwSize, dwFlags, NULL);
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
		if (lpszData)
		{
			nbCookiesEx=ExtractCookiesToken(wszUrl, lpszData,FALSE);
			if (nbCookiesEx > nbCookies)
			{
				printf("%d HttpOnly cookies found\r\n", nbCookiesEx - nbCookies);
				ExtractCookiesToken(wszUrl, lpszData, TRUE);
			}
			else
			{
				printf("No HttpOnly cookies found\r\n");
			}
		}
		else
		{
			// Allocate the necessary buffer.
			lpszData = new TCHAR[dwSize];
			wprintf(L"Allocating %d bytes and retrying.\r\n", dwSize);
			// Try the call again.
			goto retryEx;
		}

		// Release the memory allocated for the buffer.
		delete[]lpszData;
	}
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
							wprintf(L"Running at Low Integrity Level\r\n");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
							dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
						{
							// Medium Integrity
							wprintf(L"Running at Medium Integrity Level\r\n");
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
						{
							// High Integrity
							wprintf(L"Running at High Integrity Level\r\n");
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


WCHAR* ExtractSingleCookieToken(LPTSTR lpszData)
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
					wprintf(L"\tValue = %s\r\n", CookieValue);
					break;
				}
			}
			token = wcstok_s(NULL, seps, &next_token);
		}
	}
	return CookieName;
}

UINT16 ExtractCookiesToken(WCHAR* wszUrl, LPTSTR lpszData, BOOL bDisplay)
{
	// Code to display the cookie data.
	//+		lpszData	0x010dee48 L"WebLanguagePreference=fr-fr; WT_NVR=0=/:1=web; SRCHUID=V=2&GUID=9087E76D5D4343F5BFE07F75D80435E4&dmnchg=1; SRCHD=AF=NOFORM; WT_FPC=id=2186e6812f80d94b48a1502956146257:lv=1502956146257:ss=1502956146257...	wchar_t *
	// Searching token separated by ";"

	WCHAR seps[] = L";";
	WCHAR* token = NULL;
	WCHAR* next_token = NULL;
	WCHAR* CookieName = NULL;
	UINT16 CookieNumber = 0;

	//get the first token
	//Each call modifies str by substituting a null character for the first delimiter that occurs after the returned token.
	WCHAR* lpszDataCopy = new WCHAR[wcslen(lpszData) + 1];
	wcscpy_s(lpszDataCopy, wcslen(lpszData) + 1, lpszData);
	token = wcstok_s(lpszDataCopy, seps, &next_token);

	// While there are token
	while (token != NULL)
	{
		// Get next token:
		if (token != NULL)
		{
			//wprintf(L" %s\n", token);
			CookieNumber++;
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
					if (bDisplay)
					{
						wprintf(L"Cookie %d Name  = %s\r\n", CookieNumber, CookieName);
						wprintf(L"\tValue = %s\r\n", CookieValue);
						DumpCookie(wszUrl, CookieName);
					}
					break;
				}
			}
			token = wcstok_s(NULL, seps, &next_token);
		}
	}

	printf("Total number of cookies : %d\r\n", CookieNumber);
	
	//necessary for single cookie case
	return CookieNumber;
}

