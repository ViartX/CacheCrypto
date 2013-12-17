// This is the main DLL file.

#include "stdafx.h"
#include "CacheCryptoAPI.h"

wchar_t dtBuf[1024];		// temporary log output buffer
//=================================================================================================
// Class constructor, initialize fields with empty values
CacheCommon::CacheCommon()
{
	hProv = 0;
	hKey = 0;
	hHash = 0;

	globalProviderID = 0;
	globalHashAlgID = 0;
	globalSignAlgID = 0;
	globalMKS = FALSE;
	globalSilentFlag = TRUE;

	globalPIN = NULL;
	globalContainerName = NULL;
	globalProviderName = NULL;

	localString = NULL;
	localHash.data = NULL;
	localHash.len = 0;
	localSign.data = NULL;
	localSign.len = 0;
	localKey.data = NULL;
	localKey.len = 0;
}

//=================================================================================================
// Class destructor
CacheCommon::~CacheCommon()
{
	if (globalPIN) delete [] globalPIN;
	if (globalContainerName) delete [] globalContainerName;
	if (globalProviderName) delete [] globalProviderName;

	if (localString) delete [] localString;
	if (localHash.data) delete [] localHash.data;
	if (localSign.data) delete [] localSign.data;
	if (localKey.data) delete [] localKey.data;

}
//=================================================================================================
// Function initialize parameters and calls to acquire context
// provTypeId - ID of CSP
// algId	  - algorithm ID
// containerName - name of keys container, available for your CSP
// pin - pin code for selected key container
// providerName - name of selected CSP
int CacheCommon::Init(DWORD provTypeId, DWORD algId, wchar_t *containerName, wchar_t *pin, wchar_t *providerName)
{
	logMessage(L"Initializing cryptoprovider with following parameters:");
	swprintf(dtBuf, L"\tprovider type = %i", provTypeId);	logMessage(dtBuf);
	swprintf(dtBuf, L"\talgorithm ID = %i", algId);	logMessage(dtBuf);
	swprintf(dtBuf, L"\tcontainer name = %s", containerName);	logMessage(dtBuf);
	swprintf(dtBuf, L"\tcontainer pin = %s", pin);	logMessage(dtBuf);
	swprintf(dtBuf, L"\tprovider name = %s", providerName);	logMessage(dtBuf);

	globalProviderID = provTypeId;						// set provider type from procedure parameters
	globalPIN = _wcsdup(pin);							// set global PIN from procedure parameters with wide char duplicate	
	globalHashAlgID = algId;							// set hash algorithmID from procedure parameters
	
	if ((NULL != containerName) && (wcscmp(containerName, L"") != 0)) 
	{
		globalContainerName = _wcsdup(containerName);		// set keys container name from procedure parameters if it's set
	}
	if ((NULL != providerName) && (wcscmp(providerName, L"") != 0)) 
	{
		globalProviderName = _wcsdup(providerName);			// set provider name from procedure parameters with wide char duplicate 
	}

	AcquireContext();
	return 0;

}
//=================================================================================================
// update value of localString
void CacheCommon::updateLocalString(char * newString) 
{
	if (localString)
	{
		delete [] localString;
		localString = NULL;
	}
	localString = strdup(newString);

	swprintf(dtBuf, L"Local Hash updated, value is newString: %s", newString);
	logMessage(dtBuf);
}
//=================================================================================================
// update localHash
void CacheCommon::updateLocalHashString(char * newHashString, unsigned int newSize) 
{
	if (localHash.data)
	{
		delete [] localHash.data;
		localHash.data = NULL;
	}
	localHash.data = new char[newSize+1];
	memcpy(localHash.data, newHashString, newSize);
	localHash.data[newSize]=NULL;
	localHash.len = newSize;
}
//=================================================================================================
// update localSign
void CacheCommon::updateLocalSignature(char * newLocalSignature, unsigned int newSize) 
{
	if (localSign.data)
	{
		delete [] localSign.data;
		localSign.data = NULL;
	}
	localSign.data = new char[newSize+1];
	memcpy(localSign.data, newLocalSignature, newSize);
	localSign.data[newSize]=NULL;
	localSign.len = newSize;
}
//=================================================================================================
// update localKey
void CacheCommon::updateLocalKey(char * newLocalKey, unsigned int newSize)
{
	if (localKey.data)
	{
		delete [] localKey.data;
		localKey.data = NULL;
	}
	localKey.data = new char[newSize+1];
	memcpy(localKey.data, newLocalKey, newSize);
	localKey.data[newSize]=NULL;
	localKey.len = newSize;
}
//=================================================================================================
// Function acquire context, every acquired context should have corresponding ReleaseContext function
HCRYPTPROV CacheCommon::AcquireContext() {

	DWORD dwFlags = CRYPT_SILENT;
	BOOL result = FALSE;
	char* pin;

	logMessage(L"AcquireContext called...");

	if (!globalSilentFlag) 
	{
		dwFlags = 0;
	}

	if (globalMKS) 
	{
		logMessage(L"Using MACHINE_KEYSET");
		dwFlags |= CRYPT_MACHINE_KEYSET;
	}

	if (!globalContainerName) {
		if(TRUE == (result = CryptAcquireContext(&hProv, NULL, globalProviderName, globalProviderID, dwFlags))) 
		{
			swprintf(dtBuf, L"Context Acquired for provType: %d", globalProviderID);
			logMessage(dtBuf);
		}
	}
	else {
		if(TRUE == (result = CryptAcquireContext(&hProv, globalContainerName, globalProviderName, globalProviderID, dwFlags /* | CRYPT_SILENT */))) 
		{
			if (globalPIN) {
				pin = (char *)LocalAlloc(LMEM_ZEROINIT, wcslen(globalPIN)+1);
				wcstombs(pin, globalPIN, wcslen(globalPIN)+1);
				swprintf(dtBuf, L"Setting SIGNATURE_PIN=%s", globalPIN);
				logMessage(dtBuf);
				CryptSetProvParam(hProv, PP_SIGNATURE_PIN, (LPBYTE)pin, 0);
				LocalFree(pin);
			}
			swprintf(dtBuf, L"Context Acquired for ProviderType=%d, ProviderName=%s, Container=%s", globalProviderID, globalProviderName, globalContainerName);
			logMessage(dtBuf);
		}
	}

	if (result == FALSE) 
	{
		logError(L"Failed to Acquire CSP Context");
	}

	return hProv;
}

//=================================================================================================
// Function release context after its usage is finished
void CacheCommon::ReleaseContext() {
	logMessage(L"Releasing context...");
	if (hProv) {
		CryptReleaseContext(hProv, 0);
	}
	hProv = 0;
	logLastError();
}
//=================================================================================================
// output providers to log file ot console
void CacheCommon::printProviders() 
{
	DWORD dwIndex=0;
	DWORD dwType;
	DWORD cbName;
	LPTSTR pszName;

	logMessage(L"EnumProviders: ");

	while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName)) 
	{
		if (!cbName) break;

		if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return;

		if (!CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName)) 
		{ 
			logError(L"CryptEnumProviders");
			return;
		}
		swprintf(dtBuf, L"Provider Name: %s, Type: %d", pszName, dwType);
		logMessage( dtBuf );
		LocalFree(pszName);
	}

}
//=================================================================================================
// output parameters for currently selected provider, value from globalProviderID
void CacheCommon::printProviderParams() 
{
	DWORD dwIndex=0;
	BYTE pbData[1024];
	BOOL fMore = TRUE;
	HCRYPTPROV hCryptProv = 0;
	BYTE* ptr;
	ALG_ID aiAlgid;
	DWORD dwBits;
	DWORD dwNameLen;
	CHAR szName[100];
	DWORD cbData = 1024;
	DWORD dwIncrement = sizeof(DWORD);
	DWORD dwFlags = CRYPT_FIRST;
	DWORD dwParam = PP_CLIENT_HWND;
	CHAR* pszAlgType = NULL;

	DWORD provType = getGlobalProviderID();

	if (provType == 0) {
		logMessage(L"No ProviderType specified, please use provID command. Exiting");
	}

	logMessage(L"Provider Params: ");

	hCryptProv = AcquireContext();

	if (!hCryptProv) {
		logError(L"Context isn't acquired");
		return;
	}

	// Provider Name
	if(CryptGetProvParam(hCryptProv, PP_NAME, pbData, &cbData, 0)) 
	{
		swprintf(dtBuf, L"Provider Name=%S", pbData);
		logMessage( dtBuf );
	}
	else {
		logError(L"Error getting ProvName");
		return;
	}

	// Default Container
	cbData = 1024;
	if(CryptGetProvParam(hCryptProv, PP_CONTAINER, pbData, &cbData, 0)) 
	{
		swprintf(dtBuf, L"Default Container=%S", pbData);
		logMessage( dtBuf );
	}
	else {
		logError(L"Error getting default Container");
	}

	// Enumerate Algs

	logMessage(L"Enumerating the supported algorithms");

	logMessage(L"     Algid      Bits    Type               Name");
	logMessage(L"    _________________________________________________________");

	cbData = 1024;
	dwFlags = CRYPT_FIRST;
	while(fMore) {
		if(CryptGetProvParam(hCryptProv, PP_ENUMALGS, pbData, &cbData, dwFlags)) 
		{       
			dwFlags = CRYPT_NEXT;
			ptr = pbData;
			aiAlgid = *(ALG_ID *)ptr;
			ptr += sizeof(ALG_ID);
			dwBits = *(DWORD *)ptr;
			ptr += dwIncrement;
			dwNameLen = *(DWORD *)ptr;
			ptr += dwIncrement;
			strncpy_s(szName, sizeof(szName), (char *) ptr,  dwNameLen);

			//-------------------------------------------------------
			// Determine the algorithm type.
			switch(GET_ALG_CLASS(aiAlgid)) {
			case ALG_CLASS_DATA_ENCRYPT: 
				pszAlgType = "Encrypt  ";
				break;

			case ALG_CLASS_HASH:         
				pszAlgType = "Hash     ";
				break;

			case ALG_CLASS_KEY_EXCHANGE: 
				pszAlgType = "Exchange ";
				break;

			case ALG_CLASS_SIGNATURE:    
				pszAlgType = "Signature";
				break;

			default:
				pszAlgType = "Unknown  ";
				break;
			}
				
			swprintf(dtBuf,L"    %8.8d    %-4d    %S          %S",
				aiAlgid, 
				dwBits, 
				pszAlgType, 
				szName);
			logMessage( dtBuf );
		}
		else
		{
			fMore = FALSE;
		}
	}

	ReleaseContext();
}
//=================================================================================================
// Hash data string provided in parameter "hashString", stores hash result in localHash structure
// hashString - string to hash and its size
int CacheCommon::hashData(char * hashString) 
{
	swprintf(dtBuf, L"Initial string in (hashData) = %S", hashString);
	logMessage(dtBuf);

	// Create the hash object.
	if (!hashString)
	{
		logError(L"Error, no hash string passed");
		return 1;
	}

	if (hHash)
		destroyHash();

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		logMessage(L"Hash object created.");
	}
	else {
		logError(L"Error during CryptCreateHash.");
		return 1;
	}

	// Compute the cryptographic hash of the buffer.
	if(CryptHashData(hHash, (BYTE*)hashString, (DWORD)strlen(hashString), 0)) {
		updateLocalString(hashString);

		char sHashValue[MAX_HASH_SIZE];
		CryptoRecord rHash;
		getHashValue(&rHash);
		updateLocalHashString(rHash.data, rHash.len);
		logMessage(L"The data buffer has been hashed.");

		return 0;
	}
	else {
		logError(L"Error during hashData.");
	}
	return 1;
}
//=================================================================================================
// file name string provided in parameter "fileName", stores hash result in localHash structure
// hashString - string to hash and its size
int CacheCommon::hashFile(char * fileName)
{
	if (!fileName)
	{	
		logError(L"Filename not passed");
		return 1;												
	}
	
	FILE * file = fopen(fileName, "r");
	if (!file)
	{
		logError(L"Unable to open file");
		return 1;
	}

	// prepare hash structure
	if (hHash)
		destroyHash();

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		logMessage(L"Hash object created.");
	}
	else {
		logError(L"Error during CryptCreateHash.");
		return 1;
	}

	// get data from file with portions and sequentally update the hash
	char str[1024];
	while (fgets(str,1024,file))
	{
		if(!CryptHashData(hHash, (BYTE*)str, (DWORD)strlen(str), 0)) {
			logError(L"Error during hashData.");
			destroyHash();
			return 1;
		}
	}

	CryptoRecord rHash;
	getHashValue(&rHash);
	updateLocalHashString(rHash.data, rHash.len);
	logMessage(L"The data buffer has been hashed.");

	return 0;
}
//=================================================================================================
// destroy previously created hash, clear localHash structure
int CacheCommon::destroyHash()
{
	if (hHash) {
		if (CryptDestroyHash(hHash))
		{
			logMessage(L"Hash object destroyed");
			if (localHash.data)
			{
				delete [] localHash.data;
				localHash.data = NULL;
			}
			localHash.len = 0;
		}
		else
			logMessage(L"Hash object destroyed with errors");
	}
	else
	{
		logError(L"DestroyHash: Hash object does not exists (or already destroyed).");
	}
	hHash = 0;
	return 0;
}
//=================================================================================================
// Initialize hash with value
// hashVal - value of hash string, that are going to be written to hHash
int CacheCommon::initHashValue(CryptoRecord * hashVal)
{
	BYTE* pbData;
	DWORD dwSigLen;
	char buf[MAX_HASH_SIZE];
	
	if ( (!hashVal) || (!hashVal->data) || (hashVal->len==0) )
	{
		logError(L"Continue verification with previously existing hash value");
		return 0;
	}

	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, hashVal->len);
	memcpy(pbData, hashVal->data, hashVal->len);

	if (hHash) {
		logMessage(L"Destroying existing Hash object");
		destroyHash();
	}

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		logMessage(L"Hash object created.");
	}
	else {
		logError(L"Error during CryptCreateHash.");
		return 1;
	}

	ByteToStr(hashVal->len, pbData, buf);
	swprintf(dtBuf, L"Hash Received for verifying=%S", buf);
	logMessage(dtBuf);

	if (CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0)) {
		logMessage(L"CryptSetHashParam success");
	}
	else {
		logError(L"CryptSetHashParam");
		LocalFree(pbData);
		return 1;
	}
	LocalFree(pbData);
	
	return 0;
}
//=================================================================================================
// Return value of previously created hash, do not destroy hash
// hashVal - returned hash string and its size
int CacheCommon::getHashValue(CryptoRecord * hashVal)
{
	BYTE* pbData;
	DWORD pdwDataLen = 0;
	char buf[MAX_HASH_SIZE];

	if (hHash) {
		if (CryptGetHashParam(hHash, HP_HASHVAL, NULL, &pdwDataLen, 0)) {
			swprintf(dtBuf, L"Hash value data length=%d", pdwDataLen);
			logMessage(dtBuf);
			pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pdwDataLen + 1);
			if (!CryptGetHashParam(hHash, HP_HASHVAL, pbData, &pdwDataLen, 0)) {
				logError(L"CryprGetHashParam");
				LocalFree(pbData);
				return 1;
			}
			else {
				logMessage(L"CryptGetHashParam successed");
				if (hashVal)
				{
					if (hashVal->data)
					{
						delete [] hashVal->data;
					}
				hashVal->data = new char[pdwDataLen];
				memcpy(hashVal->data, pbData, pdwDataLen);
				hashVal->len = pdwDataLen;
				updateLocalHashString(hashVal->data, hashVal->len);
				}

				swprintf(dtBuf, L"HashValue=%S", pbData);
				logMessage(dtBuf);

				ByteToStr(pdwDataLen, pbData, buf);
				swprintf(dtBuf, L"pbDataHex=%S", buf);
				logMessage(dtBuf);
				LocalFree(pbData);
				return 0;
			}
		}
		else {
			logError(L"CryptGetHashParam - unable to retrieve HashValue DataLen");
		}
	}
	else {
		logError(L"Hash object does not exists");
	}
	return 1;
}
//=================================================================================================
// Create new hash string and sign it
// hashVal - string to build hash
// signVal - retuning value of signature string and its size
int CacheCommon::signNewHash(char * hashVal, CryptoRecord * signVal)
{
	DWORD dwSigLen;
	BYTE* pbSignature;

	char buf[MAX_HASH_SIZE];

	if (hashData(hashVal))
		return 1;

	// Determine the size of the signature and allocate memory.
	dwSigLen= 0;
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, 0, 0, 0, &dwSigLen)) {
		swprintf(dtBuf, L"Signature length %d found.", dwSigLen);
		logMessage(dtBuf);
	}
	else {
		logError(L"Error during CryptSignHash for dwSigLen");
		return 1;
	}

	// Allocate memory for the signature buffer.
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);

	// Sign the hash object.
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &dwSigLen)) {
		swprintf(dtBuf, L"SignatureValue=%S", pbSignature);
		logMessage(dtBuf);
		ByteToStr(dwSigLen, pbSignature, buf);
		swprintf(dtBuf, L"SignatureBytes=%S", buf);
		logMessage(dtBuf);

		if (signVal)
		{
			if (signVal->data)
				delete [] signVal->data;
		}
		signVal->data = new char[dwSigLen];
		memcpy(signVal->data, pbSignature, dwSigLen);
		signVal->len = dwSigLen;
		updateLocalSignature(signVal->data, signVal->len);
	}
	else {
		logError(L"Error during CryptSignHash.");
		LocalFree(pbSignature);
		return 1;
	}
	LocalFree(pbSignature);
	//destroyHash();
	return 0;
}
//=================================================================================================
// Sign currently available hash in system. Hash could be previously created with HashData function
// signVal - retuning value of signature string and its size
int CacheCommon::signCurrentHash(CryptoRecord * signVal) {
	DWORD dwSigLen;
	BYTE* pbSignature;

	char buf[MAX_HASH_SIZE];

	logMessage(L"SignExistingHash");

	// Determine the size of the signature and allocate memory.
	dwSigLen= 0;
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, 0, 0, 0, &dwSigLen)) {
		swprintf(dtBuf, L"Signature length %d found.", dwSigLen);
		logMessage(dtBuf);
	}
	else {
		logError(L"Error during CryptSignHash for dwSigLen");
		return 1;
	}

	// Allocate memory for the signature buffer.
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);

	// Sign the hash object.
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &dwSigLen)) {
		swprintf(dtBuf, L"SignatureValue=%S", pbSignature);	
		logMessage(dtBuf);
		ByteToStr(dwSigLen, pbSignature, buf);
		swprintf(dtBuf, L"SignatureBytes=%S", buf);
		logMessage(dtBuf);

		if (signVal)
		{
			if (signVal->data)
				delete [] signVal->data;
		}
		signVal->data = new char[dwSigLen];
		memcpy(signVal->data, pbSignature, dwSigLen);
		signVal->len = dwSigLen;
		updateLocalSignature(signVal->data, signVal->len);
	}
	else {
		logError(L"Error during CryptSignHash.");
		LocalFree(pbSignature);
		return 1;
	}
	LocalFree(pbSignature);
	//destroyHash();
	return 0;
}
//=================================================================================================
// Verify signature by hash
// hashVal - hashed string and its size
// signVal - signed hash string and its size
// result - operation result: 1-success, 0-failure
int CacheCommon::verifyHash(CryptoRecord * hashVal, CryptoRecord * signVal, int *result)
{
	BYTE* pbData = NULL;
	DWORD dwSigLen = 0;
	BYTE* pbSignature = NULL;
	char buf[MAX_HASH_SIZE];

	*result = 0;

	swprintf(dtBuf, L"Hash Received for verifying=%S", hashVal->data);
	logMessage(dtBuf);


	if (initHashValue(hashVal)==1)
	{
		logError(L"initHashValue");
		return 1;
	}	

	//Verify Signature
	if(!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		logError(L"CryptGetUserKey");
		return 1;
	}
	else {
		logMessage(L"CryptGetUserKey: public key acquired");
	}

	dwSigLen = signVal->len;
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);
	memcpy(pbSignature, signVal->data, dwSigLen);
	
	ByteToStr(dwSigLen, pbSignature, buf);
	swprintf(dtBuf, L"Signature received=%S", buf);
	logMessage(dtBuf);

	if (CryptVerifySignature(hHash, pbSignature, dwSigLen, hKey, NULL, 0)) {
		logMessage(L"Hash is verified");
		*result = 1;
	}
	else {
		logError(L"Hash is NOT verified");
	}
	LocalFree(pbSignature);
	CryptDestroyKey(hKey);

	return 0;
}
//=================================================================================================
int CacheCommon::verifySignature(char * hashString, CryptoRecord * signVal, int *result)
{
	*result = 0;
	// hash data, returned 0 is success
	if (hashData(hashString))
		return 1;
	//verify Hash, returned 0 is success
	if (verifyHash(getLocalHash(), signVal, result))
		return 1;
	
	return 0;
}
//=================================================================================================
// Verify signature by hash and key
// hashVal - hashed string and its size
// signVal - signed hash string and its size
// pubKey - key string, used to sign hash, and its size
// result - operation result: 1-success, 0-failure
int CacheCommon::verifyHashByKey(CryptoRecord * hashVal, CryptoRecord * signVal, CryptoRecord * pubKey, int * result)
{
	BYTE* pbData = NULL;
	DWORD dwSigLen = 0;
	BYTE* pbSignature = NULL;
	char buf[MAX_HASH_SIZE];

	*result = 0;

	swprintf(dtBuf, L"Hash Received for verifying=%S", hashVal->data);
	logMessage(dtBuf);

	if (initHashValue(hashVal)==1)
	{
		logError(L"initHashValue");
		return 1;
	}

	// verify signature
	if (!CryptImportKey(hProv, (BYTE*)pubKey->data, pubKey->len, 0, 0, &hKey)) {
		logError(L"CryptImportKey");
		return 1;
	}
	else {
		logMessage(L"CryptImportKey: key imported");
	}

	ByteToStr(signVal->len, signVal->data, buf);
	swprintf(dtBuf, L"Signature received=%S", buf);
	logMessage(dtBuf);

	
	// verify signature
	if (CryptVerifySignature(hHash, (BYTE*)signVal->data, signVal->len, hKey, NULL, 0)) {
		logMessage(L"Signature is verified");
		*result = 1;
	}
	else {
		logError(L"Signature is NOT verified");
	}
	LocalFree(pbSignature);
	CryptDestroyKey(hKey);

	return 0;
}
//=================================================================================================
// Build key string ready to transfer
// keyVal - resulting key string and its size, can be later transfered to recieving side
int CacheCommon::exportUserKey(CryptoRecord * keyVal) {
	BYTE* pbKeyBlob;
	DWORD dwBlobLen = 0;

	char buf[MAX_HASH_SIZE];

	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		logError(L"GetUserKey");
		return 1;
	}

	if(CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
		swprintf(dtBuf,L"Size of the BLOB for the public key=%d", dwBlobLen);
		logMessage(dtBuf);
	}
	else {
		logError(L"CryptExportKey: Error computing BLOB length");
	}

	pbKeyBlob = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dwBlobLen);

	if(CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen)) {
		ByteToStr(dwBlobLen, pbKeyBlob, buf);
		swprintf(dtBuf,L"Contents has been written to the BLOB, = %S", buf);
		logMessage(dtBuf);	
		if (keyVal)
		{
			if (keyVal->data)
				delete [] keyVal->data;
		}
		keyVal->data = new char[dwBlobLen];
		memcpy(keyVal->data, pbKeyBlob, dwBlobLen);
		keyVal->len = dwBlobLen;
	}
	else {
		logError(L"Error during CryptExportKey");
		LocalFree(pbKeyBlob);
		return 1;
	}	
	return 0;
}
//=================================================================================================
void CacheCommon::ByteToStr(
     DWORD cb, 
     void* pv, 
     LPSTR sz)
{
	BYTE* pb = (BYTE*) pv; // local pointer to a BYTE in the BYTE array
	DWORD i;               // local loop counter
	int b;                 // local variable

	// Begin processing loop.
	for (i = 0; i<cb; i++)
	{
		b = (*pb & 0xF0) >> 4;
		*sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
		b = *pb & 0x0F;
		*sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
		pb++;
	}
	*sz++ = 0;
}

//=================================================================================================
void CacheCommon::ByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr)
{
    unsigned char *p, *q;

    p = buf; 
    q = bytestr->data; 

    bytestr->len = len;
    while(len--) *q++ = *p++;

}
//=================================================================================================
void CacheCommon::ReverseByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr)
{
    unsigned char *p, *q;

    p = buf; 
    q = bytestr->data; 

    bytestr->len = len;
    while(len--) *(q + len) = *p++;

}