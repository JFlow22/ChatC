#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

#include <winsock2.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

static const BYTE rgbAES128Key[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

BCRYPT_ALG_HANDLE	hAESAlg = NULL;
BCRYPT_ALG_HANDLE	hRSAAlgo = 0;

NTSTATUS GetAESAlgorithmProvider()
{
	NTSTATUS	status = STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAESAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
	{
		printf("Problem with BCryptOpenAlgorithmProvider, error: 0x%x\n", status);
		if (hAESAlg)
			BCryptCloseAlgorithmProvider(hAESAlg, 0);
		return -1;
	}

	return 0;
}

VOID CreateAesKey(BCRYPT_KEY_HANDLE* hKey, DWORD* cbKeyObject, PBYTE* pbKeyObject)
{
	NTSTATUS		status = STATUS_UNSUCCESSFUL;
	DWORD			cbData = 0;

	if (hAESAlg == NULL)
		if (GetAESAlgorithmProvider() != 0)
			return;

	if (hAESAlg == NULL) return;

	if (!NT_SUCCESS(status = BCryptGetProperty(hAESAlg, BCRYPT_OBJECT_LENGTH,
		(PBYTE)cbKeyObject, sizeof(DWORD), &cbData, 0)))
	{
		printf("Problem with BCryptGetProperty, error: 0x%x\n", status);
	}

	*pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BYTE) * (*cbKeyObject));

	if (*pbKeyObject == NULL)
	{
		printf("Memory allocation failed!\n");
	}

	if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAESAlg, hKey,
		*pbKeyObject, *cbKeyObject, &rgbAES128Key, sizeof(rgbAES128Key), 0)))
	{
		printf("Problem with BCryptGenerateSymmetricKey, error: 0x%x\n", status);
		if (*pbKeyObject)
			HeapFree(GetProcessHeap(), 0, pbKeyObject);
	}
}

DWORD EncryptSymmetricKeyBlob(BCRYPT_KEY_HANDLE hKey, PBYTE pbPlainText, DWORD cbPlainText,
	PBYTE* pbCipherText, DWORD* cbCipherText)
{
	NTSTATUS			status = STATUS_UNSUCCESSFUL;
	DWORD				cbData = 0;

	if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL,
		NULL, 0, NULL, 0, cbCipherText, BCRYPT_PAD_PKCS1)))
	{
		printf("Problem with BCryptEncrypt1, error: 0x%x\n", status);
		return -1;
	}

	*pbCipherText = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *cbCipherText);
	if (NULL == *pbCipherText)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL,
		NULL, 0, *pbCipherText, *cbCipherText, &cbData, BCRYPT_PAD_PKCS1)))
	{
		printf("Problem with BCryptEncrypt2, error: 0x%x\n", status);
		if (*pbCipherText)
			HeapFree(GetProcessHeap(), 0, *pbCipherText);

		return -1;
	}

	return 0;
}

DWORD DecryptSymmetricKeyBlob(BCRYPT_KEY_HANDLE hKey, PBYTE pbCipherText, DWORD cbCipherText,
	PBYTE* pbPlainText, DWORD* cbPlainText)
{
	NTSTATUS			status = STATUS_UNSUCCESSFUL;
	DWORD				cbData = 0;


	if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL,
		NULL, 0, NULL, 0, cbPlainText, BCRYPT_PAD_PKCS1)))
	{
		printf("Problem with BCryptDecrypt1, error: 0x%x\n", status);
		return -1;
	}

	*pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *cbPlainText);
	if (NULL == pbCipherText)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL,
		NULL, 0, *pbPlainText, *cbPlainText, &cbData, BCRYPT_PAD_PKCS1)))
	{
		printf("Problem with BCryptEncrypt2, error: 0x%x\n", status);
		if (*pbPlainText)
			HeapFree(GetProcessHeap(), 0, *pbPlainText);

		return -1;
	}

	*cbPlainText = cbData;

	return 0;
}

DWORD EncryptMessage(BCRYPT_KEY_HANDLE hKey, PBYTE pbPlainText, DWORD cbPlainText,
	PBYTE* pbCipherText, DWORD* cbCipherText)
{
	NTSTATUS			status = STATUS_UNSUCCESSFUL;
	DWORD				cbData = 0;

	if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL,
		NULL, 0, NULL, 0, cbCipherText, BCRYPT_BLOCK_PADDING)))
	{
		printf("Problem with BCryptEncrypt1, error: 0x%x\n", status);
		goto Cleanup;
	}

	*pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *cbCipherText);
	if (NULL == *pbCipherText)
	{
		printf("Memory allocation failed!\n");
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL,
		NULL, 0, *pbCipherText, *cbCipherText, &cbData, BCRYPT_BLOCK_PADDING)))
	{
		printf("Problem with BCryptEncrypt2, error: 0x%x\n", status);
		goto Cleanup;
	}

	return 0;

Cleanup:

	if (hAESAlg)
		BCryptCloseAlgorithmProvider(hAESAlg, 0);
	if (hKey)
		BCryptDestroyKey(hKey);

	return -1;
}

DWORD DecryptMessage(BCRYPT_KEY_HANDLE hKey, PBYTE pbCipherText, DWORD cbCipherText,
	PBYTE* pbPlainText, DWORD* cbPlainText)
{
	NTSTATUS			status = STATUS_UNSUCCESSFUL;
	DWORD				cbData = 0;


	if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL,
		NULL, 0, NULL, 0, cbPlainText, BCRYPT_BLOCK_PADDING)))
	{
		printf("Problem with BCryptDecrypt1, error: 0x%x\n", status);
		return -1;
	}

	*pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *cbPlainText);
	if (NULL == pbCipherText)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL,
		NULL, 0, *pbPlainText, *cbPlainText, &cbData, BCRYPT_BLOCK_PADDING)))
	{
		printf("Problem with BCryptEncrypt2, error: 0x%x\n", status);
		if (*pbPlainText)
			HeapFree(GetProcessHeap(), 0, *pbPlainText);

		return -1;
	}

	*cbPlainText = cbData;

	return 0;
}

VOID GetRSAHandle()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hRSAAlgo, BCRYPT_RSA_ALGORITHM, NULL, 0)))
	{
		printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		if (hRSAAlgo != 0)
			BCryptCloseAlgorithmProvider(hRSAAlgo, 0);
	}
}

VOID GenerateAsymmetricKeys(BCRYPT_KEY_HANDLE* hAsymmetricKeys)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (hRSAAlgo == 0)
		GetRSAHandle();

	if (hRSAAlgo == 0) return;

	if (!NT_SUCCESS(status = BCryptGenerateKeyPair(hRSAAlgo, hAsymmetricKeys, 512, 0)))
	{
		printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		if (*hAsymmetricKeys != 0)
			BCryptDestroyKey(*hAsymmetricKeys);
	}

	if (!NT_SUCCESS(status = BCryptFinalizeKeyPair(*hAsymmetricKeys, 0)))
	{
		printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		if (*hAsymmetricKeys != 0)
			BCryptDestroyKey(*hAsymmetricKeys);
	}
}

VOID ExportPublicBlob(DWORD* dwBlobKeySize, PBYTE* pbPublicBlob, BCRYPT_KEY_HANDLE hAsymmetricKeys)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DWORD cbDataSize;

	if (hAsymmetricKeys == 0)
		GenerateAsymmetricKeys(&hAsymmetricKeys);

	if (hAsymmetricKeys == 0 || hRSAAlgo == 0) return;

	if (!NT_SUCCESS(status = BCryptExportKey(hAsymmetricKeys, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, dwBlobKeySize, 0)))
	{
		printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
	}

	*pbPublicBlob = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BYTE) * (*dwBlobKeySize));
	if (*pbPublicBlob == NULL)
	{
		printf("Memory allocation failed!\n");
		return;
	}

	if (!NT_SUCCESS(status = BCryptExportKey(hAsymmetricKeys, NULL, BCRYPT_RSAPUBLIC_BLOB, *pbPublicBlob, *dwBlobKeySize, &cbDataSize, 0)))
	{
		printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
	}

	*dwBlobKeySize = cbDataSize;
}

VOID ImportPublicBlob(CHAR* cpBlob, DWORD dwBlob, BCRYPT_KEY_HANDLE* phKey)
{
	NTSTATUS		status = STATUS_UNSUCCESSFUL;

	// get the handle to the key
	if (!NT_SUCCESS(status = BCryptImportKeyPair(hRSAAlgo, NULL, BCRYPT_RSAPUBLIC_BLOB,
		phKey, cpBlob, dwBlob, BCRYPT_NO_KEY_VALIDATION)))
	{
		printf_s("Problem in BCryptImportKey. status: 0x%x\n", status);
		return;
	}
}

VOID ExportPrivateBlob(DWORD* dwBlobKeySize, PBYTE* pbPublicBlob, BCRYPT_KEY_HANDLE hAsymmetricKeys)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DWORD cbDataSize;

	if (hAsymmetricKeys == 0)
		GenerateAsymmetricKeys(&hAsymmetricKeys);

	if (hAsymmetricKeys == 0 || hRSAAlgo == 0) return;

	if (!NT_SUCCESS(status = BCryptExportKey(hAsymmetricKeys, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, dwBlobKeySize, 0)))
	{
		printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
	}

	*pbPublicBlob = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BYTE) * (*dwBlobKeySize));
	if (*pbPublicBlob == NULL)
	{
		printf("Memory allocation failed!\n");
		return;
	}

	if (!NT_SUCCESS(status = BCryptExportKey(hAsymmetricKeys, NULL, BCRYPT_RSAPRIVATE_BLOB, *pbPublicBlob, *dwBlobKeySize, &cbDataSize, 0)))
	{
		printf("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
	}

	*dwBlobKeySize = cbDataSize;
}

VOID ImportPrivateBlob(LPSTR cpBlob, DWORD dwBlob, BCRYPT_KEY_HANDLE* phKey)
{
	NTSTATUS		status = STATUS_UNSUCCESSFUL;

	// get the handle to the key
	if (!NT_SUCCESS(status = BCryptImportKeyPair(hRSAAlgo, NULL, BCRYPT_RSAPRIVATE_BLOB,
		phKey, (PBYTE)cpBlob, dwBlob, BCRYPT_NO_KEY_VALIDATION)))
	{
		printf_s("Problem in BCryptImportKey. status: 0x%x\n", status);
		return;
	}
}

#endif