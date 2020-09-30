// internetgetcookie.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include "pch.h"
#include "stdio.h"
#include <Windows.h>
#include <WinInet.h>
#include <iepmapi.h>

#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"iepmapi.lib")

void ShowUsage()
{	
	printf("INTERNETGETCOOKIE  version 1.4\r\n");
	printf("\r\n");
	printf("pierrelc@microsoft.com August 2020\r\n");
	printf("Usage: INTERNETGETCOOKIE accepts an URL as parameter and optionaly a cookie name.\r\n");
	printf("internetgetcookie url [cookiename]\r\n");
	printf("When cookiename is used, gives the option to delete the cookie (set expiration date in the past)\r\n");
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

		wprintf(L"Calling CoInternetParseUrl  with PARSE_UNESCAPE for url : %s\r\n", wszUrl);
		HRESULT hr = CoInternetParseUrl(wszUrl, PARSE_CANONICALIZE, PARSE_UNESCAPE, szDecodedUrl,
			INTERNET_MAX_URL_LENGTH, &cchDecodedUrl, 0);
		if (hr == S_OK)
		{
			printf("CANONICALIZE: %S\n", szDecodedUrl);
			wprintf(L"Calling CoInternetParseUrl  with PARSE_SCHEMA for decoded url : %s\r\n", szDecodedUrl);
			hr = CoInternetParseUrl(szDecodedUrl, PARSE_SCHEMA, 0, szOut,
				INTERNET_MAX_URL_LENGTH, &cchDecodedUrl, 0);
			if (hr == S_OK)
				printf("SCHEME: %S\n", szOut);
			else
				printf("SCHEME: Error %08x\n", hr);

			hr = CoInternetParseUrl(szDecodedUrl, PARSE_DOMAIN, 0, szOut,
				INTERNET_MAX_URL_LENGTH, &cchDecodedUrl, 0);
			wprintf(L"Calling CoInternetParseUrl  with PARSE_DOMAIN for decoded url : %s\r\n", wszUrl);
			if (hr == S_OK)
			{
				printf("DOMAIN: %S\n", szOut);
				unsigned long InternetGetCookieState = 0L;
				wprintf(L"Calling InternetGetPerSiteCookieDecisionW for domain : %s\r\n", szOut);
				if (InternetGetPerSiteCookieDecisionW(szOut, &InternetGetCookieState))
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
				}
				else
				{
					wprintf(L"InternetGetPerSiteCookieDecisionW returning false.\r\n\r\n");
				}
			}
			else
				printf("DOMAIN: Error %08x\n", hr);
		}
		else
			printf("CANONICALIZE: Error %08x\n", hr);
		
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
						printf("This is a protected mode url so the tool needs to be run from a low integrity process.\r\n");
						//IEGetProtectedModeCookie requires a cookie name!
						exit(1L);
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

