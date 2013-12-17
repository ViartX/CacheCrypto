// CacheCryptoAPI.h

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <wchar.h>
#include <time.h>
#include <Windows.h>
#include <WinCrypt.h>

#include "callin.h"
#include "cdzf.h"
#include "CacheLogger.h"

//using namespace System;

#define MAX_HASH_SIZE 4096
#define MAX_SIGN_SIZE 4096
#define MAX_DATA_SIZE 32768

struct CryptoRecord
{
	char * data;
	unsigned int len;
	CryptoRecord() {data=NULL; len=0;};
};

class CacheCommon : public CacheLogger
{
	// Class variables
	HCRYPTPROV hProv;				// descriptor of CSP, that is created by CryptAcquireContext
	HCRYPTKEY hKey;					// descriptor of key, created by CryptGetUserKey
	HCRYPTHASH hHash;				// descriptor of hash, created in hashData function

	DWORD globalProviderID;			// id of CSP
	DWORD globalHashAlgID;			// id of hash algorithm, can be used instead of globalSignAlgID
	DWORD globalSignAlgID;			// id of sign algorithm
	BOOL globalMKS;					// flag of machine keyset usage
	BOOL globalSilentFlag;			// flag of providing operations in silent mode

	wchar_t* globalPIN;				// pincode to reach keys
	wchar_t* globalContainerName;	// name of CSP keys container
	wchar_t* globalProviderName;	// name of CSP

	char* localString;				// string, basement for Hash string creation, last entered value
	CryptoRecord localHash;			// hash value, last created with hashData or signNewHash methods
	CryptoRecord localSign;			// signature value, last created with signNewHash or signCurrentHash methods
	CryptoRecord localKey;			// key value, generated with exportUserKey method

// Methods
public:
	CacheCommon();
	~CacheCommon();

	BOOL getGlobalMKS()	{return globalMKS;};				// get value of globalMKS (machine key set flag), inline method
	void setGlobalMKS(BOOL newMKS) {globalMKS=newMKS;};		// set value of globalMKS, inline method

	wchar_t* getGlobalProviderName() {return globalProviderName;};		// get value of globalProviderName, inline method
	void setGlobalProviderName(wchar_t * newGlobalProviderName) {globalProviderName = _wcsdup(newGlobalProviderName);};		// set value of globalProviderName, inline method

	wchar_t* getGlobalContainerName() {return globalContainerName;};	// get value of globalContainerName, inline method
	void setGlobalContainerName(wchar_t * newGlobalContainerName) {globalContainerName = _wcsdup(newGlobalContainerName);};	// set value of globalContainerName, inline method

	wchar_t* getGlobalPIN() {return globalPIN;};		// get value of globalPIN, inline method
	void setGlobalPIN(wchar_t * newGlobalPIN) {globalPIN = _wcsdup(newGlobalPIN);};		// set value of globalPIN, inline method

	DWORD getGlobalProviderID() {return globalProviderID;};			// get value of globalPIN, inline method
	void setGlobalProviderID(DWORD newGlobalProviderID) {globalProviderID = newGlobalProviderID;};		// set value of globalPIN, inline method

	DWORD getGlobalAlgID() {return globalHashAlgID;};				// get value of globalHashAlgID, inline method
	void setGlobalAlgID(DWORD newGlobalHashAlgID) {globalHashAlgID = newGlobalHashAlgID;};			// set value of globalHashAlgID, inline method

	char * getLocalString() {return localString;};	// get value of localString
	void updateLocalString(char * newString);		// update value of localString

	char * getLocalHashString() {return localHash.data;};		// get value of localHash.data, inline method
	void updateLocalHashString(char * newHashString, unsigned int newSize);		// update localHash
	unsigned int getHashLength() {return localHash.len;};		// get value of localHash.len, inline method
	void setHashLength(unsigned int newHashLength) {localHash.len = newHashLength;};	// set value of localHash.len, inline method
	CryptoRecord * getLocalHash() {return &localHash;};			// get pointer of localHash structure, inline method

	char * getLocalSignature() {return localSign.data;};		// get value of localSign.data, inline method
	void updateLocalSignature(char * newLocalSignature, unsigned int newSize);		// update localSign
	unsigned int getSignatureLength() {return localSign.len;};		// get value of localSign.len, inline method
	void setSignatureLength(unsigned int newSignatureLength) {localSign.len = newSignatureLength;};		// set value of localSign.len, inline method
	CryptoRecord * getLocalSign() {return &localSign;};			// get pointer of localSign structure, inline method

	CryptoRecord * getLocalKey() {return &localKey;};			// get pointer of localKey structure, inline method
	void updateLocalKey(char * newLocalKey, unsigned int newSize);	// update localKey

	int Init(DWORD provTypeId, DWORD algId, wchar_t *containerName, wchar_t *pin, wchar_t *providerName);	// initialize fields with values from function parameters and calls AcquireContext
	HCRYPTPROV AcquireContext();						// acquires context
	void ReleaseContext();								// releases context
	void printProviders();								// output available providers to file or console
	void printProviderParams();							// output parameters of provider to file or console
	int hashData(char * hashString);					// hash data
	int hashFile(char * fileName);						// hash file content
	int destroyHash();									// empty hHash pointer
	int initHashValue(CryptoRecord * hashVal);			// create new hash object and initialize it with hashVal value
	int getHashValue(CryptoRecord * hashVal = NULL);		// get hash value into hashVal, if hashVal is NULL, just log it
	int signNewHash(char * hashVal, CryptoRecord * signVal);	// create new hash and sign it, signVal returns signature
	int signCurrentHash(CryptoRecord * signVal);				// sign currently existing hash, returns signature in signVal
	int verifyHash(CryptoRecord * hashVal, CryptoRecord * signVal, int *result);		// verify if the signVal is correct for provided hashVal
	int verifyHashByKey(CryptoRecord * hashVal, CryptoRecord * signVal, CryptoRecord * pubKey, int * result);		// verify if the signVal is correct for provided hashVal with additional public key
	int verifySignature(char * hashString, CryptoRecord * signVal, int *result);		// verify if the signVal is correct for provided string. First create hash for string hashVal, then verify signature
	int exportUserKey(CryptoRecord * keyVal);

	// Utils
	static void ByteToStr(DWORD cb, void* pv, LPSTR sz);
	static void ByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr);
	static void ReverseByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr);		
};
