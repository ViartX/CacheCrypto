// This is the main DLL file.

#include "stdafx.h"
#include "ISCAPI.h"

#define ZF_DLL
#include "cdzf.h"
#include "..\CacheCryptoAPI\CacheCryptoAPI.h"

CacheCommon cacheCommon;
//=================================================================================================
// Print cryptographic providers currently available in OS
int printProviders()
{
	cacheCommon.printProviders();
	return 0;
}
//=================================================================================================
// Initialization of cryptoprovider
// provTypeId - ID of CSP
// algId	  - algorithm ID
// containerName - name of keys container, available for your CSP
// pin - pin code for selected key container
// providerName - name of selected CSP
int Init(DWORD provTypeId, DWORD algId, wchar_t *containerName, wchar_t *pin, wchar_t *providerName)
{
	cacheCommon.Init(provTypeId, algId, containerName, pin, providerName);	// set parameters and acquire context
	return 0;
}
//=================================================================================================
// Acquire context function, should be called before other operations with CSP
int AcquireContext()
{
	cacheCommon.AcquireContext();
	return 0;
}
//=================================================================================================
// Release acquired earlier context. Should pair all AcquireContext functions, otherwise slow down operational performance on server
int ReleaseContext()
{
	cacheCommon.ReleaseContext();
	return 0;
}
//=================================================================================================
// Hash data string provided in parameter "dataToHash"
// dataToHash - string to hash and its size
int HashData(ZARRAYP dataToHash)
{
	// transition to avoid bad strings from COS CALLOUT
	char cData[MAX_DATA_SIZE];
	sprintf(cData, "%s", dataToHash->data);
	cData[dataToHash->len]=NULL;
	cacheCommon.hashData(cData);

	return 0;
}
//=================================================================================================
// Hash file, file name is provided in parameter "fileName"
int HashFile(ZARRAYP fileName)
{
	// transition to avoid bad strings from COS CALLOUT
	char cFileName[1024];
	sprintf(cFileName, "%s", fileName->data);
	cFileName[fileName->len]=NULL;
	cacheCommon.hashFile(cFileName);

	return 0;
}
//=================================================================================================
// Return value of previously created hash
// hashVal - returned hash string and its size
int GetHashValue(ZARRAYP hashVal)
{
	CryptoRecord tempHash;
	cacheCommon.getHashValue(&tempHash);
	cacheCommon.ByteToZARRAY(tempHash.len, (BYTE*)tempHash.data, hashVal);
	hashVal->data[hashVal->len]=NULL;

	wchar_t dtBuf[1024];
	swprintf(dtBuf, L"Hash at Class side: %S, length: %i", cacheCommon.getLocalHashString(), cacheCommon.getHashLength());
	cacheCommon.logMessage(dtBuf);
	return 0;
}
//=================================================================================================
// Sign currently available hash in system. Hash could be previously created with HashData function
// signVal - retuning value of signature string and its size
int SignCurrentHash(ZARRAYP signVal)
{
	CryptoRecord tempSign;
	cacheCommon.signCurrentHash(&tempSign);

	cacheCommon.ByteToZARRAY(tempSign.len, (BYTE*)tempSign.data, signVal);
	signVal->data[signVal->len]=NULL;

	wchar_t dtBuf[1024];
	swprintf(dtBuf, L"Signature at Class side: %S, length: %i", cacheCommon.getLocalSignature(), cacheCommon.getSignatureLength());
	cacheCommon.logMessage(dtBuf);

	return 0;
}
//=================================================================================================
// Create new hash string and sign it
// hashVal - string to build hash and its size
// signVal - retuning value of signature string and its size
int SignNewHash(ZARRAYP hashVal, ZARRAYP signVal)
{
	cacheCommon.signNewHash((char*)hashVal->data, cacheCommon.getLocalSign());
	cacheCommon.ByteToZARRAY(cacheCommon.getSignatureLength(), (BYTE*)cacheCommon.getLocalSignature(), signVal);
	return 0;
}
//=================================================================================================
// Verify signature by hash
// hashVal - hashed string
// signVal - signed hash string
// result - operation result: 1-success, 0-failure
int VerifyHash(ZARRAYP hashVal, ZARRAYP signVal, int *result)
{
	// copy hashVal and signVal to local structures
	cacheCommon.updateLocalHashString((char*)hashVal->data, hashVal->len);
	cacheCommon.updateLocalSignature((char*)signVal->data, signVal->len);

	// use local copies to verify signature
	cacheCommon.verifyHash(cacheCommon.getLocalHash(), cacheCommon.getLocalSign(), result);
	return 0;
}
//=================================================================================================
// Verify signature by initial string
// dataToHash - initial string
// signVal - signed hash string
// result - operation result: 1-success, 0-failure
int VerifySignature(ZARRAYP dataToHash, ZARRAYP signVal, int *result)
{
	// transition to avoid bad strings from COS CALLOUT
	char cData[MAX_DATA_SIZE];
	sprintf(cData, "%s", dataToHash->data);
	cData[dataToHash->len]=NULL;
	cacheCommon.updateLocalString(cData);

	cacheCommon.updateLocalSignature((char*)signVal->data, signVal->len);

	// use local copies to verify signature
	cacheCommon.verifySignature(cacheCommon.getLocalString(), cacheCommon.getLocalSign(), result);
	return 0;
}
//=================================================================================================
// Verify signature by hash and key
// hashVal - hashed string
// signVal - signed hash string
// keyVal - key string, used to sign hash
// result - operation result: 1-success, 0-failure
int VerifyHashByKey(ZARRAYP hashVal, ZARRAYP signVal, ZARRAYP keyVal, int *result)
{
	// copy hashVal and signVal to local structures
	cacheCommon.updateLocalHashString((char*)hashVal->data, hashVal->len);
	cacheCommon.updateLocalSignature((char*)signVal->data, signVal->len);
	cacheCommon.updateLocalKey((char*)keyVal->data, keyVal->len);

	// use local copies to verify signature
	cacheCommon.verifyHashByKey(cacheCommon.getLocalHash(), cacheCommon.getLocalSign(), cacheCommon.getLocalKey(), result);
	return 0;
}
//=================================================================================================
// Build key string ready to transfer
// keyVal - resulting key string and its size, can be later transfered to recieving side
int ExportKey(ZARRAYP keyVal)
{
	cacheCommon.exportUserKey(cacheCommon.getLocalKey());
	cacheCommon.ByteToZARRAY(cacheCommon.getLocalKey()->len, (BYTE*)cacheCommon.getLocalKey()->data, keyVal);
	return 0;
}
//=================================================================================================
// Release resourses, hash and context
int ReleaseAll()
{
	cacheCommon.destroyHash();
	ReleaseContext();
	return 0;
}
//=================================================================================================
// Initialize Logger fnctionality
// logFileName - name of file
// logLevel - 0-none, 1-only errors, 2- all events
// logTargets - 1-file, 2-console, 3-both
int InitLogger(wchar_t* logFileName, int logLevel, int logTargets) 
{
	cacheCommon.setLogLevel(logLevel);
	cacheCommon.setLogFileName(logFileName);
	cacheCommon.setLogTargets(logTargets);
	cacheCommon.setLogSourceLocation(0);
	return 0;
}
//=================================================================================================
// Output one log message
// msg - text of message
int LogMessageCOS(wchar_t* msg) 
{
	cacheCommon.logMessage(msg);
	return 0;
}
//=================================================================================================
ZFBEGIN
	ZFENTRY("LogMessage", "w", LogMessageCOS)
	ZFENTRY("Init", "iiwww", Init)
	ZFENTRY("InitLogger", "wii", InitLogger)
	ZFENTRY("AContext", "", AcquireContext)
	ZFENTRY("RContext", "", ReleaseContext)
	ZFENTRY("HashData", "b", HashData)
	ZFENTRY("HashFile", "b", HashFile)
	ZFENTRY("GetHashValue", "B", GetHashValue)
	ZFENTRY("SignCurrentHash", "B", SignCurrentHash)
	ZFENTRY("SignNewHash", "bB", SignNewHash)
	ZFENTRY("VerifyHash", "bbP", VerifyHash)
	ZFENTRY("VerifyHashByKey", "bbbP", VerifyHashByKey)
	ZFENTRY("VerifySignature", "bbP", VerifySignature)
	ZFENTRY("ExportUserKey", "B", ExportKey)
	ZFENTRY("PrintProviders", "", printProviders)
	ZFENTRY("ReleaseAll", "", ReleaseAll)
ZFEND
