#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>
#include <bcrypt.h>

#define STATUS_SUCCESS 0
#define RSA_KEY_STANDARD 2048

#pragma comment (lib , "Bcrypt.lib")

int main(int argc, char **argv)
{
	BCRYPT_ALG_HANDLE algHandle;
	BCRYPT_KEY_HANDLE keyHandle;
	ULONG size, t;
	std::ifstream file_to_encrypt;
	std::streampos begin, end;
	int siz;
	PCHAR memblock;
	UCHAR iv[sizeof(DWORD)];

	// set up RSA keys
	if (BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_RSA_ALGORITHM, NULL, 0) != STATUS_SUCCESS)
		return -1;

	if (BCryptGenerateKeyPair(algHandle, &keyHandle, RSA_KEY_STANDARD, 0) != STATUS_SUCCESS)
		return -1;

	if (BCryptFinalizeKeyPair(keyHandle, 0) != STATUS_SUCCESS)
		return -1;

	// open file to encrypt
	file_to_encrypt.open("C:\\Users\\111ol\\Desktop\\test.txt", std::ios::binary);

	begin = file_to_encrypt.tellg();
	file_to_encrypt.seekg(0, std::ios::end);
	end = file_to_encrypt.tellg();
	siz = end - begin;

	int siz1 = siz;

	memblock = new CHAR[siz + 1];
	memset(memblock, 0, siz + 1);
	file_to_encrypt.seekg(std::ios::beg);
	file_to_encrypt.read(memblock, siz);

	// prepare for encryption
	BCRYPT_OAEP_PADDING_INFO paddingInformation;
	memset(&paddingInformation, 0, sizeof(BCRYPT_OAEP_PADDING_INFO));
	paddingInformation.pszAlgId = BCRYPT_SHA512_ALGORITHM;

	if (BCryptEncrypt(keyHandle, (PUCHAR)memblock, siz, &paddingInformation, NULL, 0,
		NULL, 0, &size, BCRYPT_PAD_OAEP) != STATUS_SUCCESS)
		return -1;

	UCHAR *encrypted = new UCHAR[size + 100];
	memset(encrypted, 0, size + 100);

	// encrypt the memory buffer
	if (BCryptEncrypt(keyHandle, (PUCHAR)memblock, siz, &paddingInformation, NULL, 0,
		encrypted, size, &size, BCRYPT_PAD_OAEP) != STATUS_SUCCESS)
		return -1;

	// try to decrypt the buffer into a new buffer
	UCHAR *decrypted = new UCHAR[siz];
	if (BCryptDecrypt(keyHandle, encrypted, size, &paddingInformation, NULL, 0, decrypted,
		siz, &size, BCRYPT_PAD_OAEP) != STATUS_SUCCESS)
		return -1;

	// export public key 
	if (BCryptExportKey(keyHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &size, NULL) != STATUS_SUCCESS)
		return -1;

	CHAR *blobPublic = new CHAR[size + 1];
	memset(blobPublic, 0, size + 1);
	if (BCryptExportKey(keyHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, (PUCHAR)blobPublic, size, &size, NULL) != STATUS_SUCCESS)
		return -1;

	std::ofstream rsaPublicKey;
	rsaPublicKey.open("C:\\Users\\111ol\\Desktop\\PublicRSAKey.pem", std::ios::binary);
	rsaPublicKey.write(blobPublic, size);
	rsaPublicKey.close();

	// export private key
	if (BCryptExportKey(keyHandle, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &size, NULL) != STATUS_SUCCESS)
		return -1;

	CHAR *blobPrivate = new CHAR[size + 1];
	memset(blobPrivate, 0, size + 1);
	if (BCryptExportKey(keyHandle, NULL, BCRYPT_RSAPRIVATE_BLOB, (PUCHAR)blobPrivate, size, &size, NULL) != STATUS_SUCCESS)
		return -1;

	std::ofstream rsaPrivateKey;
	rsaPrivateKey.open("C:\\Users\\111ol\\Desktop\\PrivateRSAKey.pem", std::ios::binary);
	rsaPrivateKey.write(blobPrivate, size);
	rsaPrivateKey.close();

	// close algorithm provider
	BCryptCloseAlgorithmProvider(algHandle, 0);

	// read the public key from the file
	std::ifstream keyPair;
	keyPair.open("C:\\Users\\111ol\\Desktop\\PrivateRSAKey.pem", std::ios::binary);

	begin = keyPair.tellg();
	keyPair.seekg(0, std::ios::end);
	end = keyPair.tellg();
	siz = end - begin;

	CHAR *keyPairBlob = new CHAR[siz];
	keyPair.seekg(std::ios::beg);
	keyPair.read(keyPairBlob, siz);

	BCRYPT_KEY_HANDLE keyHandleBlob;
	BCRYPT_ALG_HANDLE algHandleBlob;
	DWORD s;
	ULONG k;

	// open a new algorithm provider
	if (BCryptOpenAlgorithmProvider(&algHandleBlob, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) != STATUS_SUCCESS)
		return -1;

	// import the public key
	if ((s = BCryptImportKeyPair(algHandleBlob, NULL, BCRYPT_PRIVATE_KEY_BLOB, &keyHandleBlob, (UCHAR *)keyPairBlob,
		siz, 0)) != STATUS_SUCCESS) {
		DWORD error = GetLastError();
		return -1;
	}

	// encrypt the test file with the public key
	BCRYPT_OAEP_PADDING_INFO paddingInformation2;
	memset(&paddingInformation2, 0, sizeof(BCRYPT_OAEP_PADDING_INFO));
	paddingInformation2.pszAlgId = BCRYPT_SHA512_ALGORITHM;

	if (BCryptEncrypt(keyHandleBlob, (PUCHAR)memblock, siz1, &paddingInformation2, NULL, 0,
		NULL, 0, &k, BCRYPT_PAD_OAEP) != STATUS_SUCCESS)
		return -1;

	UCHAR *encrypted2 = new UCHAR[k + 1];
	memset(encrypted2, 0, k + 1);

	if((s = BCryptEncrypt(keyHandleBlob, (PUCHAR)memblock, siz1, &paddingInformation2, NULL, 0,
		encrypted2, k, &k, BCRYPT_PAD_OAEP)) != STATUS_SUCCESS)
		return -1;

	return 0;
}