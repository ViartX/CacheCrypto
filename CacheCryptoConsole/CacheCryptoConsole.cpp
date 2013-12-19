// CacheCryptoConsole.cpp : Defines the entry point for the console application.
//Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider
// s cl = ##class(iscapi.Signer).%New()
// s st = cl.LoadDLL("c:\ARTEM\ISCAPI1.dll")
// s st = cl.InitCSP()

#include "stdafx.h"
#include "conio.h"
#include "string.h"
#include <iostream>
#include <vector>
#include <cstdio>

#include "..\CacheCryptoAPI\CacheCryptoAPI.h"


using namespace std;

CacheCommon * cacheCommon;
CryptoRecord signature;
CryptoRecord key;
char tempHash[MAX_HASH_SIZE];
wchar_t tBuf[1024];

//=================================================================================================
// function set console window parameters
void setWindow()
{
	// set window size
	HANDLE out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD crd = {1000, 800};
	SMALL_RECT src = {0, 0, crd.X-1, crd.Y-1};
	SetConsoleWindowInfo (out_handle, true, &src);
	SetConsoleScreenBufferSize (out_handle, crd);
	HWND hwnd;      

	wchar_t Title[1024];
	GetConsoleTitle(Title, 1024);
	hwnd=FindWindow(NULL, Title);
	MoveWindow(hwnd,20,20,1000,800,TRUE);
}

//=================================================================================================
// function shows available commands
void show_usage()
{
	// show usage
	printf("Usage:\n");

	printf("   help()\n");
	printf("\t    ... show available commands\n");

	printf("   showProviders()\n");
	printf("\t    ... show providers available in system\n");

	printf("   showProvParams()\n");
	printf("\t    ... show provider parameters available in system\n");

	printf("   print()\n");
	printf("\t    ... show current set values\n");

	printf("   arContext(int ProviderType)\n");
	printf("\t    ... acquire and release context for provider\n");

	printf("   aContext(int ProviderType)\n");
	printf("\t    ... acquire context for provider\n");

	printf("   rContext(int ProviderType)\n");
	printf("\t    ... release context for provider\n");

	printf("   hashData(string textToHash)\n");
	printf("\t    ... hash data string\n");

	printf("   hashFile(string fileName)\n");
	printf("\t    ... hash file\n");

	printf("   getHashValue\n");
	printf("\t    ... get hash Value\n");

	printf("   signCurrentHash()\n");
	printf("\t    ... sign existing hash \n");

	printf("   signNewHash(string textToHash)\n");
	printf("\t    ... create new hash and sign it\n");

	printf("   destroyHash()\n");
	printf("\t    ... clear hash object\n");

	printf("   verifyHash()\n");
	printf("\t    ... verify signature by hash\n");

	printf("   verifyHashByKey()\n");
	printf("\t    ... verify signature by hash and key\n");

	printf("   verifySignature(string textToHash)\n");
	printf("\t    ... verify signatue by initial string\n");

	printf("   exportKey()\n");
	printf("\t    ... export key \n");

	printf("   provID(int Provider ID)\n");
	printf("\t    ... set provider ID \n");

	printf("   algID(int Algorithm ID)\n");
	printf("\t    ... set algorithm ID \n");

	printf("   contName(string Container Name ID)\n");
	printf("\t    ... set container name ID \n");

	printf("   provName(string Provider Name ID)\n");
	printf("\t    ... set provider name ID \n");	

	printf("   contPIN(string PIN)\n");
	printf("\t    ... set new PIN \n");	

}
//=================================================================================================
// function clears vector, free all alocated memory
int clear_vector(std::vector<wchar_t*> &myVec)
{
	int i;
	for(i=0; i<(int)myVec.size(); ++i)
		delete[] myVec[i];
	myVec.clear();
	return i;
}
//=================================================================================================
// function parses string on vector of parameters
int parse_params(wchar_t * commandStr, std::vector<wchar_t *>  &params)
{
	int ret = 0;
	if (!commandStr)
		return ret;

	clear_vector(params);

	bool openedQuote = false;
	int startPos=0;
	for (int i=0; i<=wcslen(commandStr); ++i)
	{
		if (commandStr[i]=='"')
		{
			openedQuote=!openedQuote;
			continue;
		}

		if ((commandStr[i]==0x20) || (commandStr[i]==NULL))
		{
			if (openedQuote) continue;
			if ( (i-startPos)>=1)	//avoids two following spaces
			{
				wchar_t * param = new wchar_t[i-startPos+1];
				wcsncpy(param, commandStr+startPos, i-startPos);
				param[i-startPos]=NULL;
				if (param[0]=='"')		// trim string from quotes
				{
					wchar_t * newParam = new wchar_t[wcslen(param)-2+1];
					wcsncpy(newParam, param+1, wcslen(param)-2);
					newParam[wcslen(param)-2]=NULL;
					delete[] param;
					param=newParam;
				}
				params.push_back(param);
			}				
			startPos=i+1;
		}
	}
	return params.size();
}
//=================================================================================================
//output list of available providers and their types
void showProviders() {
	cacheCommon->printProviders();
}
//=================================================================================================
// aquire context for internal calls
HCRYPTPROV simpleAC(DWORD provType) 
{
	cacheCommon->setGlobalProviderID(provType);
	return  cacheCommon->AcquireContext();
}
//=================================================================================================
// release context for internal calls
void simpleRC(HCRYPTPROV hCryptProv) 
{
	cacheCommon->ReleaseContext();
}
//=================================================================================================
// show parameters of selected provider
void showProviderParams() {
	cacheCommon->printProviderParams();
}
//=================================================================================================
//test acquiring and releasing context
void acquireReleaseContext(DWORD provType) {

	simpleAC(provType);
	simpleRC(provType);
}
//=================================================================================================
//aqcuire context
void acquireContext(DWORD provType) {
	simpleAC(provType);
}
//=================================================================================================
//release context
void releaseContext(DWORD provType) {
	simpleRC(provType);
}
//=================================================================================================
// create a hash based on sData string
void HashData(wchar_t * sData)
{
	if (!sData)
		cacheCommon->logMessage(L"No data to hash");

	char cData[MAX_DATA_SIZE];
	sprintf(cData, "%S", sData);
	cacheCommon->hashData(cData);
}
//=================================================================================================
// create a hash based on sData string
void HashFile(wchar_t * sFileName)
{
	if (!sFileName)
		cacheCommon->logMessage(L"No file specified");

	char cFileName[1024];
	sprintf(cFileName, "%S", sFileName);
	cacheCommon->hashFile(cFileName);
}
//=================================================================================================
// get and log hash string
void GetHashValue()
{
	wchar_t * hashVal = NULL;
	cacheCommon->getHashValue();

	return;
}
//=================================================================================================
// create a hash and sign it
// sHash - string, used to create hash string
void SignNewHash(wchar_t * sHash)
{
	// create ZARRAYP structure from wchar_t input string
	if (!sHash)
		cacheCommon->logMessage(L"No data to hash");

	char cHash[MAX_DATA_SIZE];
	sprintf(cHash, "%S", sHash);


	CacheCommon * tmp = cacheCommon;
	cacheCommon->signNewHash(cHash, &signature);
	// after copying signature, pointer to cacheCommon changes to random value for safety reasons, so for further work need to take it back 
	if (tmp!=cacheCommon)
		cacheCommon = tmp;
	return;

}
//=================================================================================================
// create signature based on the current hash string
void SignCurrentHash()
{
	CacheCommon * tmp = cacheCommon;
	cacheCommon->signCurrentHash(&signature);
	// after copying signature, pointer to cacheCommon changes to random value for safety reasons, so for further work need to take it back 
	if (tmp!=cacheCommon)
		cacheCommon = tmp;
}
//=================================================================================================
// verify signature, based on current internal values
void VerifyHash()
{
	int result;
	cacheCommon->verifyHash(cacheCommon->getLocalHash(), &signature, &result);
	return;
}
//=================================================================================================
// verify signature with key
void VerifyHashByKey()
{
	int result;
	cacheCommon->verifyHashByKey(cacheCommon->getLocalHash(), &signature, &key, &result);
	return;
}
//=================================================================================================
// verify signature, based on current internal values
void VerifySignature(wchar_t * sHash)
{
	// create ZARRAYP structure from wchar_t input string
	if (!sHash)
		cacheCommon->logMessage(L"No data to hash");

	char cHash[MAX_DATA_SIZE];
	sprintf(cHash, "%S", sHash);

	int result;
	cacheCommon->verifySignature(cHash, &signature, &result);
	return;
}
//=================================================================================================
// test exportKey functionality, put key into local key variable
void ExportKey()
{
	cacheCommon->exportUserKey(&key);
	return;
}
//=================================================================================================
// set provider type from console
void setProviderType(DWORD provTypeID)
{
	cacheCommon->setGlobalProviderID(provTypeID);
}
//=================================================================================================
// set algorithm ID from console
void setAlgID(DWORD algID)
{
	cacheCommon->setGlobalAlgID(algID);
}
//=================================================================================================
// set container name from console
void setContainerName(wchar_t * newContainerName)
{
	if ((NULL != newContainerName) && (wcscmp(newContainerName, L"") != 0)) 
	{
		cacheCommon->setGlobalContainerName(newContainerName);
	}
}
//=================================================================================================
// set provider name from console
void setProviderName(wchar_t * newProviderName)
{
	if ((NULL != newProviderName) && (wcscmp(newProviderName, L"") != 0)) 
	{
		cacheCommon->setGlobalProviderName(newProviderName);
	}
}
//=================================================================================================
// set keys container pin sode from console
void setContainerPIN(wchar_t * newPIN)
{
	if ((NULL != newPIN) && (wcscmp(newPIN, L"") != 0)) 
	{
		cacheCommon->setGlobalPIN(newPIN);
	}
}
//=================================================================================================
// destroy local hash
void DestroyHash()
{
	cacheCommon->destroyHash();
}
//=================================================================================================
// print settings for current CSP
void printSettings()
{
	DWORD globalW;
	wchar_t * globalC;

		globalW = cacheCommon->getGlobalProviderID();
		swprintf(tBuf, L"Provider ID: %d", globalW);
		cacheCommon->logMessage( tBuf );

		globalC = cacheCommon->getGlobalProviderName();
		swprintf(tBuf, L"Provider Name: %s", globalC);
		cacheCommon->logMessage( tBuf );

		globalW = cacheCommon->getGlobalAlgID();
		swprintf(tBuf, L"Algorithm ID: %d", globalW);
		cacheCommon->logMessage( tBuf );

		globalC = cacheCommon->getGlobalContainerName();
		swprintf(tBuf, L"Container Name: %s", globalC);
		cacheCommon->logMessage( tBuf );

		globalC = cacheCommon->getGlobalPIN();
		swprintf(tBuf, L"Container PIN: %s", globalC);
		cacheCommon->logMessage( tBuf );

}
//=================================================================================================
// fill automaticly test data for debug purposes
void fillTestData()
{
	cacheCommon->Init(75, 32798, L"CacheCrypt", L"", L"Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider");	// set parameters and acquire context
	cacheCommon->setLogTargets(3);								// additional parameters for logging settings
	cacheCommon->setLogFileName(L"c:\\iscapi.log");		// additional parameter for file name in logging settings
	printSettings();
}
//=================================================================================================
//fulfill operations
bool doCommand(std::vector<wchar_t*> * params)
{
	if (!params) return false;
	
	if( !wcscmp((*params)[0], L"help") )
		show_usage();
	else if( !wcscmp((*params)[0], L"showProviders") )
		showProviders();
	else if( !wcscmp((*params)[0], L"showProvParams") )
		showProviderParams();
	else if( !wcscmp((*params)[0], L"print") )
		printSettings();
	else if ( ( !wcscmp((*params)[0], L"arContext") ) && (params->size()==2) )
		acquireReleaseContext(_wtoi((*params)[1]));
	else if ( ( !wcscmp((*params)[0], L"aContext") ) && (params->size()==2) )
		acquireContext(_wtoi((*params)[1]));
	else if ( ( !wcscmp((*params)[0], L"rContext") ) && (params->size()==2) )
		releaseContext(_wtoi((*params)[1]));
	else if ( ( !wcscmp((*params)[0], L"provID") ) && (params->size()==2) )
		setProviderType(_wtoi((*params)[1]));
	else if ( ( !wcscmp((*params)[0], L"algID") ) && (params->size()==2) )
		setAlgID(_wtoi((*params)[1]));
	else if ( ( !wcscmp((*params)[0], L"contName") ) && (params->size()==2) )
		setContainerName( (wchar_t*)((*params)[1]) );
	else if ( ( !wcscmp((*params)[0], L"provName") ) && (params->size()==2) )
		setProviderName( (wchar_t*)((*params)[1]) );
	else if ( ( !wcscmp((*params)[0], L"contPIN") ) && (params->size()==2) )
		setContainerPIN( (wchar_t*)((*params)[1]) );
	else if ( ( !wcscmp((*params)[0], L"hashData") ) && (params->size()==2) )
		HashData( (wchar_t*)((*params)[1]) );
	else if ( ( !wcscmp((*params)[0], L"hashFile") ) && (params->size()==2) )
		HashFile( (wchar_t*)((*params)[1]) );
	else if ( !wcscmp((*params)[0], L"getHashValue") )
		GetHashValue();	
	else if  ( !wcscmp((*params)[0], L"destroyHash") )
		DestroyHash();
	else if ( !wcscmp((*params)[0], L"signCurrentHash") )
		SignCurrentHash();
	else if ( ( !wcscmp((*params)[0], L"signNewHash") ) && (params->size()==2) )
		SignNewHash( (wchar_t*)((*params)[1]) );
	else if (  !wcscmp((*params)[0], L"verifyHash")  )
		VerifyHash();
	else if (  (!wcscmp((*params)[0], L"verifySignature")  ) && (params->size()==2) ) 
		VerifySignature((wchar_t*)((*params)[1]));
	else if (  !wcscmp((*params)[0], L"verifyHashByKey")  )
		VerifyHashByKey();
	else if (  !wcscmp((*params)[0], L"exportKey")  )
		ExportKey();

	else if (  !wcscmp((*params)[0], L"fill")  )
		fillTestData();

	return true;
}
//=================================================================================================
int main(int argc, wchar_t* argv[])
{
	setlocale(LC_CTYPE, "rus");
	cacheCommon = new(CacheCommon);
	cacheCommon->setLogLevel(LOGLEVELALL);

	cacheCommon->setLogFileName(LOGFILENAME);
	cacheCommon->setLogTargets(LOGTARGETCONSOLE);
	cacheCommon->setLogSourceLocation(0);

	wchar_t command[1024];
	std::vector<wchar_t*> params;

	setWindow();
	show_usage();
	do
	{
		printf("\n>");
		_getws(command);
		int count = wcslen(command);

		if (count>0)
		{	
			int nParams = parse_params(command, params);
			doCommand(&params);
		}

	}
	while ( wcscmp(command,L"exit") && wcscmp(command,L"quit") );

	clear_vector(params);

	return 0;
}

