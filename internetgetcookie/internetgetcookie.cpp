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
	printf("Usage: INTERNETGETCOOKIE accepts an URL as parameter.\r\n");
	printf("See https://docs.microsoft.com/en-us/windows/win32/wininet/managing-cookies\r\n");
	printf("and https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetgetcookieexa");
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		ShowUsage();
		exit(0L);
	}
	WCHAR wszUrl[INTERNET_MAX_URL_LENGTH];
	MultiByteToWideChar(CP_ACP, 0, argv[1], strlen(argv[1]), wszUrl, INTERNET_MAX_URL_LENGTH);
	wszUrl[strlen(argv[1])] = 0;
	wprintf(L"Calling InternetGetCookie for url %s\r\n", wszUrl);

	LPTSTR lpszData = NULL;   // buffer to hold the cookie data
	DWORD dwSize = 0;           // variable to get the buffer size needed
	BOOL bReturn;
	// Insert code to retrieve the URL.

retry:
	// The first call to InternetGetCookie will get the required
	// buffer size needed to download the cookie data.
	bReturn = InternetGetCookie(wszUrl, NULL, lpszData, &dwSize);
	if (bReturn  == FALSE)
	{
		DWORD dwError = GetLastError();
		// Check for an insufficient buffer error.
		if (dwError == ERROR_INSUFFICIENT_BUFFER)
		{
			// Allocate the necessary buffer.
			lpszData = new TCHAR[dwSize];

			// Try the call again.
			goto retry;
		}
		else
		{
			// Error handling code.			
			if (dwError == ERROR_NO_MORE_ITEMS)
			{
				printf("There is no cookie for the specified URL and all its parents.");
				exit(1L);
			}
			else
			{
				printf("InternetGetCookie failed with error %d", dwError);
				exit(-1L);
			}
		}
	}
	else
	{
		if (lpszData)
		{
			// Code to display the cookie data.
			printf("Cookie data : %S\r\n\r\n", lpszData);
			//+		lpszData	0x010dee48 L"WebLanguagePreference=fr-fr; WT_NVR=0=/:1=web; SRCHUID=V=2&GUID=9087E76D5D4343F5BFE07F75D80435E4&dmnchg=1; SRCHD=AF=NOFORM; WT_FPC=id=2186e6812f80d94b48a1502956146257:lv=1502956146257:ss=1502956146257...	wchar_t *
			// Searching token separated by ";"
			WCHAR seps[] = L";";
			WCHAR *token = NULL;
			WCHAR *next_token = NULL;

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
						if (*(token+i )== L'=')
						{
							*(token + i) = '\0';
							WCHAR *CookieName = token;
							//strip initial space if needed
							if (CookieName[0] == ' ')
							{ 
								CookieName += 1;
							}
							WCHAR *CookieValue = token + i + 1;
							wprintf(L"Name=%s", CookieName);
							wprintf(L";Value=%s\r\n", CookieValue);

							LPTSTR lpszDataEx = NULL;   // buffer to hold the cookie data
							wprintf(L"Calling InternetGetCookieEx for url %s and cookie name %s and flag INTERNET_COOKIE_THIRD_PARTY\r\n", wszUrl, CookieName);
retryEx:								
							bReturn = InternetGetCookieEx(wszUrl, CookieName, lpszDataEx, &dwSize, INTERNET_COOKIE_THIRD_PARTY, NULL);
							if (bReturn == FALSE)
							{
								if (lpszDataEx)
								{
									printf("No Third party cookie\r\n");
								}
								DWORD dwError = GetLastError();
								// Check for an insufficient buffer error.
								if (dwError == ERROR_INSUFFICIENT_BUFFER)
								{
									// Allocate the necessary buffer.
									lpszDataEx = new TCHAR[dwSize];

									// Try the call again.
									goto retryEx;
								}
								else
								{
									// Error handling code.			
									if (dwError == ERROR_NO_MORE_ITEMS)
									{
										printf("There is no cookie for the specified URL and all its parents.");
										exit(1L);
									}
									else
									{
										printf("InternetGetCookieEx failed with error %d", dwError);
										exit(-1L);
									}
								}
							}
							else
							{
								if (lpszDataEx)
								{
									printf("Third party cookie\r\n");
								}
								else
								{

									// Allocate the necessary buffer.
									lpszDataEx = new TCHAR[dwSize];

									// Try the call again.
									goto retryEx;

								}
								
							}

							break;
						}
					}
					token = wcstok_s(NULL, seps, &next_token);
				}
			}
		}  //end if lpszData
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
	return 0L;
}

