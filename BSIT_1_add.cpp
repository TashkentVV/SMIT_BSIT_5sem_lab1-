#include <iostream>
#include <iomanip>

#include <wchar.h>

#include <strsafe.h>
#include <WbemIdl.h>
#include <wincred.h>
#include <comdef.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")

#define _WIN32_DCOM
#define UNICODE

#define REMOTE_COMPUTER_NAME L"QWE"

INT printError(CONST CHAR* message, HRESULT code = 0x00)
{
	std::cout << "Error: " << message << std::endl;
	std::cout << "Code: " << std::hex << code << std::endl;
	return EXIT_FAILURE;
}

INT __cdecl main(INT argc, CHAR** argv)
{
	// step 1 - COM initialize
	setlocale(LC_ALL, "Russian");
	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);

	if (FAILED(hres))
		return printError("CoInitializeEx()", hres);

	// step 2 - security

	hres = CoInitializeSecurity(
		NULL,
		-1,      // COM negotiates service                  
		NULL,    // Authentication services
		NULL,    // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
		RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
		NULL,             // Authentication info 
		EOAC_NONE,        // Additional capabilities
		NULL              // Reserved
	);

	if (FAILED(hres))
	{
		CoUninitialize();
		return printError("CoInitializeSecurity()", hres);
	}

	// step 3 - create locator WMI

	IWbemLocator* pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hres))
	{
		CoUninitialize();
		return printError("CoCreateInstance()", hres);
	}

	// step 4 - get credentials

	BOOL useToken = FALSE, useNTLM = TRUE, fSave = FALSE;

	wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
	wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
	wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
	wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };

	wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1];
	wchar_t pszNetworkRecource[CREDUI_MAX_USERNAME_LENGTH + 1];

	CREDUI_INFO cui = { 0 };
	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	cui.pszMessageText = TEXT("Press cancel to use process token");
	cui.pszCaptionText = TEXT("Enter Account Information");
	cui.hbmBanner = NULL;

	DWORD dwErr = CredUIPromptForCredentials(
		&cui,
		TEXT(""),
		NULL,
		0,
		pszName,
		CREDUI_MAX_USERNAME_LENGTH + 1,
		pszPwd,
		CREDUI_MAX_PASSWORD_LENGTH + 1,
		&fSave,
		CREDUI_FLAGS_GENERIC_CREDENTIALS |
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);

	if (dwErr == ERROR_CANCELLED)
		useToken = TRUE;
	else if (dwErr)
	{
		pLoc->Release();
		CoUninitialize();
		return printError("CredUIPromptForCredentials()", dwErr);
	}

	// step 5 - IWbemLocator::ConnectServer

	if (!useNTLM)
		StringCchPrintf(
			pszAuthority, CREDUI_MAX_USERNAME_LENGTH + 1, L"kERBEROS:%s", REMOTE_COMPUTER_NAME);

	StringCchPrintf(
		pszNetworkRecource, CREDUI_MAX_USERNAME_LENGTH + 1, L"\\\\%s\\root\\cimv2", REMOTE_COMPUTER_NAME);

	IWbemServices* pSvc = NULL;

	hres = pLoc->ConnectServer(
		_bstr_t(pszNetworkRecource),
		_bstr_t(useToken ? NULL : pszName),    // User name
		_bstr_t(useToken ? NULL : pszPwd),     // User password
		NULL,                              // Locale             
		NULL,                              // Security flags
		_bstr_t(useNTLM ? NULL : pszAuthority),// Authority        
		NULL,                              // Context object 
		&pSvc                              // IWbemServices proxy
	);

	if FAILED(hres)
	{
		pLoc->Release();
		CoUninitialize();
		return printError("ConnectServer()", hres);
	}

	std::cout << std::endl;
	std::cout << ">> Connection to ROOT\\CIMV2 successful" << std::endl;
	std::cout << std::endl;

	// step 6 - COAUTHIDENTITY 

	COAUTHIDENTITY* userAcct = NULL;
	COAUTHIDENTITY authIdent;

	if (!useToken)
	{
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;

		LPWSTR slash = wcschr(pszName, L'\\');

		if (NULL == slash)
		{
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return printError("wcschr()");
		}

		StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
		authIdent.User = (USHORT*)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);

		StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);
		authIdent.Domain = (USHORT*)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

		userAcct = &authIdent;
	}

	// step 7 - set proxy

	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);

	if FAILED(hres)
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("CoSetProxyBlanket()", hres);
	}

	// step 8 - Use the IWbemServices pointer to make requests of WMI

	// OS info

	IEnumWbemClassObject* pEnumerator = NULL;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from Win32_OperatingSystem"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("ExecQuery() OS info", hres);
	}

	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("CoSetProxyBlanket() enumenator", hres);
	}

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	std::cout << "OS info:" << std::endl;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn)
			break;

		VARIANT vtProp;

		pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		//*(vtProp.bstrVal + 32) = '\0';
		std::wcout << "Name: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
		std::wcout << "Organization: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
		std::wcout << "SerialNumber: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"SystemDirectory", 0, &vtProp, 0, 0);
		std::wcout << "SystemDirectory: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
		std::wcout << "Version: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"BuildNumber", 0, &vtProp, 0, 0);
		std::wcout << "BuildNumber: " << vtProp.bstrVal << std::endl;

		pclsObj->Get(L"RegisteredUser", 0, &vtProp, 0, 0);
		std::wcout << "RegisteredUser: " << vtProp.bstrVal << std::endl;

		pclsObj->Release();
		pclsObj = NULL;
	}

	std::cout << std::endl;

	// Apps info

	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from Win32_Product"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("ExecQuery() Apps info", hres);
	}

	hres = CoSetProxyBlanket(
		pEnumerator,                    // Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		userAcct,                       // client identity
		EOAC_NONE                       // proxy capabilities 
	);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("CoSetProxyBlanket() enumenator", hres);
	}

	std::cout << "Apps info:" << std::endl;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
			break;

		VARIANT vtProp;

		hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		std::wcout << vtProp.bstrVal << std::endl;

		VariantClear(&vtProp);

		pclsObj->Release();
		pclsObj = NULL;
	}

	// cleanup

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	if (pclsObj)
		pclsObj->Release();

	// connect ROOT\SecurityCenter2

	StringCchPrintf(
		pszNetworkRecource, CREDUI_MAX_USERNAME_LENGTH + 1, L"\\\\%s\\root\\SecurityCenter2", REMOTE_COMPUTER_NAME);

	hres = pLoc->ConnectServer(
		_bstr_t(pszNetworkRecource),
		_bstr_t(useToken ? NULL : pszName),
		_bstr_t(useToken ? NULL : pszPwd),
		NULL,
		NULL,
		_bstr_t(useNTLM ? NULL : pszAuthority),
		NULL,
		&pSvc
	);

	if (FAILED(hres))
	{
		pLoc->Release();
		CoUninitialize();
		return printError("ConnectServer() SecurityCenter2", hres);
	}

	std::cout << std::endl;
	std::cout << ">> Connection to ROOT\\SecurityCenter2 successful" << std::endl;
	std::cout << std::endl;

	userAcct = NULL;

	if (!useToken)
	{
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT*)pszPwd;

		LPWSTR slash = wcschr(pszName, L'\\');

		if (NULL == slash)
		{
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return printError("wcschr()");
		}

		StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
		authIdent.User = (USHORT*)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);

		StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);
		authIdent.Domain = (USHORT*)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

		userAcct = &authIdent;
	}

	hres = CoSetProxyBlanket(
		pSvc,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("CoSetProxyBlanket()", hres);
	}

	// Anti-spyware info

	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from AntiSpywareProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("ExecQuery() Anti-spyware info", hres);
	}

	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);

	if (FAILED(hres))
	{
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("CoSetProxyBlanket()", hres);
	}

	std::cout << "Anti-spyware info:" << std::endl;

	bool key = false;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
		{
			if (key == false)
				std::cout << ">> Not install" << std::endl;
			break;
		}

		key = true;
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		std::wcout << "Name: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "File path: " << vtProp.bstrVal << std::endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	std::cout << std::endl;

	// Antiviruses info

	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from AntiVirusProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("ExecQuery() Antiviruses info", hres);
	}

	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);

	if (FAILED(hres))
	{
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("CoSetProxyBlanket()", hres);
	}

	std::cout << "Antiviruses info:" << std::endl;

	key = false;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
		{
			if (key == false)
				std::cout << ">> Not install" << std::endl;
			break;
		}

		key = true;
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		std::wcout << "Name: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "File path: " << vtProp.bstrVal << std::endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}

	std::cout << std::endl;

	// Firewalls info

	pEnumerator = NULL;
	pclsObj = NULL;
	uReturn = 0;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("Select * from FirewallProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("ExecQuery() Firewalls info", hres);
	}

	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE
	);

	if (FAILED(hres))
	{
		pEnumerator->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return printError("CoSetProxyBlanket()", hres);
	}

	std::cout << "Firewalls info:" << std::endl;

	key = false;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
		{
			if (key == false)
				std::cout << ">> Not install" << std::endl;
			break;
		}

		key = true;
		VARIANT vtProp;

		hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
		std::wcout << "Name: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
		std::wcout << "GUID: " << vtProp.bstrVal << std::endl;

		hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
		std::wcout << "File path: " << vtProp.bstrVal << std::endl;
		std::cout << std::endl;

		VariantClear(&vtProp);
		pclsObj->Release();
		pclsObj = NULL;
	}


	// global cleanup

	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	SecureZeroMemory(pszUserName, sizeof(pszUserName));
	SecureZeroMemory(pszDomain, sizeof(pszDomain));

	pSvc->Release();
	pEnumerator->Release();
	if (pclsObj)
		pclsObj->Release();
	CoUninitialize();

	return EXIT_SUCCESS;
}
