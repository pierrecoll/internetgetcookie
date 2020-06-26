// internetgetcookie.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include "pch.h"
#include "stdio.h"
#include <Windows.h>
#include <WinInet.h>

#pragma comment(lib,"wininet.lib")

void ShowUsage()
{	
	printf("INTERNETGETCOOKIE  version 1.2\r\n");
	printf("\r\n");
	printf("pierrelc@microsoft.com June 2020\r\n");
	printf("Usage: INTERNETGETCOOKIE accepts an URL as parameter and optionaly a cookie name.\r\n");
	printf("internetgetcookie url [cookiename]\r\n");
	printf("See https://docs.microsoft.com/en-us/windows/win32/wininet/managing-cookies\r\n");
	printf("and https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetgetcookieexa");
}

void ExtractToken(LPTSTR lpszData)
{
	// Code to display the cookie data.
	//+		lpszData	0x010dee48 L"WebLanguagePreference=fr-fr; WT_NVR=0=/:1=web; SRCHUID=V=2&GUID=9087E76D5D4343F5BFE07F75D80435E4&dmnchg=1; SRCHD=AF=NOFORM; WT_FPC=id=2186e6812f80d94b48a1502956146257:lv=1502956146257:ss=1502956146257...	wchar_t *
	// Searching token separated by ";"

	WCHAR seps[] = L";";
	WCHAR* token = NULL;
	WCHAR* next_token = NULL;

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
					WCHAR* CookieName = token;
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
}

int main(int argc, char* argv[])
{
	if ((argc != 2) && (argc != 3))
	{
		ShowUsage();
		exit(0L);
	}
	WCHAR wszUrl[INTERNET_MAX_URL_LENGTH]=L"";
	WCHAR wszCookieName[INTERNET_MAX_URL_LENGTH] = L"";
	MultiByteToWideChar(CP_ACP, 0, argv[1], strlen(argv[1]), wszUrl, INTERNET_MAX_URL_LENGTH);
	wszUrl[strlen(argv[1])] = 0;
	wprintf(L"Url : %s\r\n", wszUrl);


	if (argc == 2)
	{
		/*unsigned long InternetGetCookieState=0L;
		if (InternetGetPerSiteCookieDecisionW(L"microsoft.com", &InternetGetCookieState))
		{
			wprintf(L"InternetGetPerSiteCookieDecisionW returning cookie state : %X\r\n", InternetGetCookieState);
			switch (InternetGetCookieState)
			{
			case COOKIE_STATE_UNKNOWN:
				wprintf(L"COOKIE_STATE_UNKNOWN\r\n");
				break;
			case COOKIE_STATE_ACCEPT:
				wprintf(L"COOKIE_STATE_ACCEPT\r\n");
				break;
			case COOKIE_STATE_PROMPT:
				wprintf(L"COOKIE_STATE_PROMPT\r\n");
				break;
			case COOKIE_STATE_LEASH:
				wprintf(L"COOKIE_STATE_LEASH\r\n");
				break;
			case COOKIE_STATE_DOWNGRADE:
				wprintf(L"COOKIE_STATE_DOWNGRADE\r\n");
				break;
			case COOKIE_STATE_REJECT:
				wprintf(L"COOKIE_STATE_REJECT\r\n");
				break;
			default:
				wprintf(L"COOKIE_STATE_UNKNOWN\r\n");
				break;
			}
		}*/


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
				wprintf(L"Allocating %d bytes and retrying\r\n", dwSize);
				// Try the call again.
				goto retry;
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
					printf("InternetGetCookie failed with error %d\r\n", dwError);
					exit(-1L);
				}
			}
		}
		else
		{
			printf("InternetGetCookie succeeded\r\n");
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
				goto retry;
			}

			// Release the memory allocated for the buffer.
			delete[]lpszData;
		}
	}
	if (argc == 3)
	{

		MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]), wszCookieName, INTERNET_MAX_URL_LENGTH);
		wszUrl[strlen(argv[1])] = 0;
		wprintf(L"Cookie Name : %s\r\n", wszCookieName);
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
			wprintf(L"HttpOnly cookie\r\n");
			if (lpszCookieData)
			{
				wprintf(L"Cookie data :%s\r\n", lpszCookieData);
				ExtractToken(lpszCookieData);
			}
			else
			{
				wprintf(L"No Cookie data. If NULL is passed to lpszCookieData, the call will succeed and the function will not set ERROR_INSUFFICIENT_BUFFER\r\n");
				wprintf(L"allocating %d bytes and retrying\r\n", dwSize);
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

