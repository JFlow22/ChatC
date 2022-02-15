#include "ChatClient/Client.h"

CHAR				lpsUsername[SIZE_USERNAME]	= "";
DWORD				dwPipesCount				= 0;
SOCKET				sokClientSocket				= 0;
WSADATA				wsa;
BCRYPT_KEY_HANDLE	hEncrytionKey				= 0;
BCRYPT_KEY_HANDLE	hAsymmetricKeys				= 0;
pipeHandleList_t*	pipeHandlesListHead			= NULL;
PBYTE				pbKeyObject					= NULL;
BOOL				bIsAdmin					= FALSE;

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

DWORD IndexUntilDelim(CHAR cDelim, LPSTR lpsStringToSearch, DWORD dwStringSize)
{
	for (DWORD dwLocationInString = 0; dwLocationInString < dwStringSize; dwLocationInString++)
	{
		if (lpsStringToSearch[dwLocationInString] == cDelim)
			return dwLocationInString;
	}

	return -1;
}

LPHANDLE GetHandlesByName(LPSTR lpsPipeName)
{
	pipeHandleList_t* handlesIter = pipeHandlesListHead;

	while (handlesIter != NULL)
		if (strcmp(handlesIter->lpsPipeName, lpsPipeName) == 0)
			break;
		else
			handlesIter = handlesIter->nextPipesHandle;

	if (handlesIter == NULL)	return NULL;

	return handlesIter->lphPipeHandles;
}

pipeHandleList_t* GetLastPipeHandles()
{
	pipeHandleList_t* handlesIter = pipeHandlesListHead;

	if (handlesIter == NULL)
		return NULL;

	while (handlesIter->nextPipesHandle != NULL)
			handlesIter = handlesIter->nextPipesHandle;

	return handlesIter;
}

VOID ReleasePipeHandlesList(pipeHandleList_t* handlesIter)
{
	if (handlesIter == NULL)
		return;

	if (handlesIter->lphPipeHandles[0] != NULL)
		CloseHandle(handlesIter->lphPipeHandles[0]);

	if (handlesIter->lphPipeHandles[1] != NULL)
		CloseHandle(handlesIter->lphPipeHandles[1]);

	if (handlesIter->lpsPipeName != NULL)
		HeapFree(GetProcessHeap(), 0, handlesIter->lpsPipeName);

	ReleasePipeHandlesList(handlesIter->nextPipesHandle);
}

VOID PipeHandlesListInit()
{
	pipeHandlesListHead = (pipeHandleList_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(pipeHandleList_t));
	if (pipeHandlesListHead == NULL)
	{
		printf_s("Problem with HeapAlloc, PipeHandlesListInit\n");
		return;
	}

	pipeHandlesListHead->nextPipesHandle = NULL;
	pipeHandlesListHead->lpsPipeName = NULL;
	pipeHandlesListHead->lphPipeHandles[0] = NULL;
	pipeHandlesListHead->lphPipeHandles[1] = NULL;
}

VOID DeleteHandlesFromList(LPSTR lpsHandlesName)
{
	pipeHandleList_t* handlesIter = pipeHandlesListHead;
	pipeHandleList_t* handlesToDelete = NULL;

	if (handlesIter == NULL)
	{
		printf_s("No such handles found, DeleteHandlesFromList\n");
		return;
	}

	if (handlesIter->nextPipesHandle == NULL)
	{
		if (!strcmp(handlesIter->lpsPipeName, lpsHandlesName))
		{
			if (handlesIter->lphPipeHandles[0] != NULL)
				CloseHandle(handlesIter->lphPipeHandles[0]);

			if (handlesIter->lphPipeHandles[1] != NULL)
				CloseHandle(handlesIter->lphPipeHandles[1]);
			
			if (handlesIter->lpsPipeName != NULL)
				HeapFree(GetProcessHeap(), 0, handlesIter->lpsPipeName);

			HeapFree(GetProcessHeap(), 0, handlesIter);

			pipeHandlesListHead = NULL;

			return;
		}
	}

	while (handlesIter->nextPipesHandle != NULL)
	{
		if (!strcmp(handlesIter->nextPipesHandle->lpsPipeName, lpsHandlesName))
		{
			handlesToDelete = handlesIter->nextPipesHandle;
			break;
		}

		handlesIter = handlesIter->nextPipesHandle;
	}

	if (handlesToDelete != NULL)
	{
		handlesIter->nextPipesHandle = handlesToDelete->nextPipesHandle;

		if (handlesToDelete->lphPipeHandles[0] != NULL)
			CloseHandle(handlesToDelete->lphPipeHandles[0]);

		if (handlesToDelete->lphPipeHandles[1] != NULL)
			CloseHandle(handlesToDelete->lphPipeHandles[1]);

		if (handlesToDelete->lpsPipeName != NULL)
			HeapFree(GetProcessHeap(), 0, handlesToDelete->lpsPipeName);

		HeapFree(GetProcessHeap(), 0, handlesToDelete);
	}
}

pipeHandleList_t* CreateNewPipeHandlesInList()
{
	pipeHandleList_t* pipesHandleIter = pipeHandlesListHead;

	if (pipeHandlesListHead == NULL)
	{
		pipeHandlesListHead = (pipeHandleList_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(pipeHandleList_t));
		if (pipeHandlesListHead == NULL)
		{
			printf_s("Problem with HeapAlloc, CreateNewPipeHandlesInList\n");
			return NULL;
		}

		pipeHandlesListHead->nextPipesHandle = NULL;
		return pipeHandlesListHead;
	}

	while (pipesHandleIter->nextPipesHandle != NULL)
	{
		pipesHandleIter = pipesHandleIter->nextPipesHandle;
	}

	pipesHandleIter->nextPipesHandle = (pipeHandleList_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(pipeHandleList_t));
	if (pipesHandleIter->nextPipesHandle == NULL)
	{
		printf_s("Problem with HeapAlloc, CreateNewPipeHandlesInList\n");
		return NULL;
	}

	pipesHandleIter->nextPipesHandle->nextPipesHandle = NULL;
	return pipesHandleIter->nextPipesHandle;
}

DWORD InitWinsock()
{
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d",WSAGetLastError());
		return 1;
	}

	printf("Initialised.\n");
	return 0;
}

DWORD ConnectSocket()
{
	struct	sockaddr_in server;

	if (InitWinsock())
		return -1;

	if ((sokClientSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
		return -1;
	}

	InetPtonA(AF_INET, SERVER_IP_ADDR, &(server.sin_addr.s_addr));
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT_NUM);

	if (connect(sokClientSocket, (struct sockaddr*) & server, sizeof(server)) < 0)
	{
		puts("connect error\n");
		return -1;
	}

	return 0;
}

DWORD Login()
{
	DWORD cbPublicBlobSize = 0;
	PBYTE pbPublicBlob = NULL;
	DWORD cbPrivateBlobSize = 0;
	PBYTE pbPrivateBlob = NULL;
	chat_message_t sendingMessage;
	chat_message_t receivingMessage;
	BCRYPT_KEY_HANDLE hPrivateKey = NULL;
	BCRYPT_KEY_HANDLE hPublicKey = NULL;
	PBYTE pbBlob = NULL;
	DWORD cbBlob = 0;

	printf_s("-----Welcome to the chat!-----\nUsername: ");
	scanf_s("%s", lpsUsername, SIZE_USERNAME);

	if (lpsUsername == 0)	return 1;

	if (ConnectSocket())
	{
		printf_s("Problem with ConnectSocket\n");
		return -1;
	}

	CreateChatMessage(OP_LOGIN_REQUEST, (DWORD)strlen(lpsUsername), lpsUsername, &sendingMessage);

	if (SendChatMessage(sokClientSocket, NULL, sendingMessage) != 0)
	{
		printf_s("Send failed, Login\n");
		return -1;
	}

	if (ReceiveChatMessage(sokClientSocket, NULL, &receivingMessage) != 0)
	{
		printf_s("Receive failed, Login\n");
		return -1;
	}

	while (receivingMessage.Header[0] == OP_LOGIN_FAILED)
	{
		ResetChatMessage(&sendingMessage);

		printf_s("%s", receivingMessage.Data);
		printf_s("Username: ");
		scanf_s("%s", lpsUsername, SIZE_USERNAME);

		CreateChatMessage(OP_LOGIN_REQUEST, (DWORD)strlen(lpsUsername), lpsUsername, &sendingMessage);

		if (SendChatMessage(sokClientSocket, NULL, sendingMessage) != 0)
		{
			printf_s("Send failed, Login\n");
			return -1;
		}

		ResetChatMessage(&receivingMessage);

		if (ReceiveChatMessage(sokClientSocket, NULL, &receivingMessage) != 0)
		{
			printf_s("Receive failed, Login\n");
			return -1;
		}
	}

	ResetChatMessage(&sendingMessage);

	GenerateAsymmetricKeys(&hAsymmetricKeys);

	ExportPublicBlob(&cbPublicBlobSize, &pbPublicBlob, hAsymmetricKeys);
	ExportPrivateBlob(&cbPrivateBlobSize, &pbPrivateBlob, hAsymmetricKeys);

 	ImportPublicBlob(pbPublicBlob, cbPublicBlobSize, &hPublicKey);

	CreateChatMessage(OP_REPLY_ASYMMETRIC_KEY, cbPublicBlobSize, (CHAR*)pbPublicBlob, &sendingMessage);

	if (SendChatMessage(sokClientSocket, NULL, sendingMessage) != 0)
	{
		printf_s("Send failed, Login\n");
		return -1;
	}

	ResetChatMessage(&receivingMessage);

	if (ReceiveChatMessage(sokClientSocket, NULL, &receivingMessage) != 0)
	{
		printf_s("Receive failed, Login\n");
		return -1;
	}

	ImportPrivateBlob((CHAR*)pbPrivateBlob, cbPrivateBlobSize, &hPrivateKey);

	if (DecryptSymmetricKeyBlob(hPrivateKey, (PBYTE)(receivingMessage.Data),
		GetDataSizeFromMessage(receivingMessage), &pbBlob, &cbBlob) != 0)
	{
		printf_s("Problem with EncryptSymmetricKeyBlob, ClientLogin\n");
		return -1;
	}

	GetEncryptionKey((CHAR*)pbBlob, cbBlob); // receiving data is blob
	printf_s("%s logged in to the server!\n", lpsUsername);

	ResetChatMessage(&sendingMessage);
	ResetChatMessage(&receivingMessage);		

	if (ReceiveChatMessage(sokClientSocket, NULL, &receivingMessage) != 0)
	{
		printf_s("Receive failed, Login\n");
		return -1;
	}

	if (receivingMessage.Header[0] == OP_LOGIN_AS_ADMIN)
		bIsAdmin = TRUE;
	else if (receivingMessage.Header[0] == OP_LOGIN_AS_NORMAL)
		bIsAdmin = FALSE;

	BCryptDestroyKey(hPrivateKey);

	return 0;
}

DWORD OptionsMenu()
{
	DWORD dwOptionChosen;

	printf_s("Options:\n1 - Watch online users\n2 - Create private chat with a user\n3 - Watch chat groups\n4 - Create chat group\n5 - Join chat group\n");
	if (bIsAdmin)
		printf_s("6 - Admin: Send message to all chats\n7 - Admin: Close chat room\n");
	printf_s("0 - Exit chat\nYour choice : ");
	scanf_s("%d", &dwOptionChosen);

	return dwOptionChosen;
}



DWORD GetEncryptionKey(LPSTR cpBlob, DWORD dwBlob)
{
	DWORD			dwBlobSize = 0;
	DWORD			cbData = 0;
	DWORD			cbKeyObject = 0;
	NTSTATUS		status = STATUS_UNSUCCESSFUL;

	GetAESAlgorithmProvider();

	if (!NT_SUCCESS(status = BCryptGetProperty(hAESAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject,
		sizeof(DWORD), &cbData, 0)))
	{
		printf_s("Problem in BCryptGetProperty. status: 0x%x", status);
		goto Cleanup;
	}

	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbKeyObject);
	if (pbKeyObject == NULL)
	{
		printf_s("Problem with HeapAlloc\n");
		goto Cleanup;
	}

	// get the handle to the key
	if (!NT_SUCCESS(status = BCryptImportKey(hAESAlg, NULL, BCRYPT_KEY_DATA_BLOB,
		&hEncrytionKey, pbKeyObject, cbKeyObject, (PBYTE)cpBlob, dwBlob, 0)))
	{
		printf_s("Problem in BCryptImportKey. status: 0x%x\n", status);
		goto Cleanup;
	}

	return 0;

Cleanup:
	if (cpBlob)
		HeapFree(GetProcessHeap(), 0, cpBlob);
	if (hAESAlg)
		BCryptCloseAlgorithmProvider(hAESAlg, 0);
	if (pbKeyObject)
		HeapFree(GetProcessHeap(), 0, pbKeyObject);

	return -1;
}

VOID PrintAllUserNames(LPSTR lpsAllUserNames)
{
	printf_s("List of clients: \n%s", lpsAllUserNames);
}

VOID ClientListPrintHandle(chat_message_t receivingMessage)
{
	printf_s("---------------------------------\n");
	printf_s("List of clients: \n%s", receivingMessage.Data);
	printf_s("---------------------------------\n");
}

VOID ChatRoomListPrintHandle(chat_message_t receivingMessage)
{
	printf_s("---------------------------------\n");
	printf_s("List of chat rooms: \n%s", receivingMessage.Data);
	printf_s("---------------------------------\n");
}

DWORD WINAPI ReceiveFromProcessThreadHandle(LPVOID lpParams)
{
	threadParams_t* tpParams = (threadParams_t*)lpParams;
	DWORD dwRead;
	LPSTR lpsReceivingMessage = NULL;
	DWORD dwReceivingMessageSize;
	chat_message_t sendingMessage;
	LPHANDLE lphPipesHandles = NULL; 
	LPSTR lpsDataToSend = NULL;
	DWORD dwDatatoSendSize;
	CHAR lpsReadHeader[HEADER_SIZE] = "";
	DWORD dwLastError = 0;

	lphPipesHandles = GetHandlesByName(tpParams->lpsChatName);
	do {
		if (!ReadFile(lphPipesHandles[0], &lpsReadHeader, HEADER_SIZE, &dwRead, NULL))
		{
			if ((dwLastError = GetLastError()) != 109)
			{
				printf_s("Problem with ReadFile. last error: %d\n", dwLastError);
				return -1;
			}

			break;
		}
		else
		{
			dwReceivingMessageSize = lpsReadHeader[1] + (lpsReadHeader[2] << 8) + 1;
			if (tpParams->bIsPrivate)
			{
				dwDatatoSendSize = dwReceivingMessageSize + (DWORD)strlen(tpParams->lpsChatName) + (DWORD)strlen(lpsUsername) + 2;
			}
			else
				dwDatatoSendSize = dwReceivingMessageSize + (DWORD)strlen(tpParams->lpsChatName) + 1;

			lpsReceivingMessage = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwReceivingMessageSize);
			if (lpsReceivingMessage == NULL)
			{
				printf_s("Problem with HeapAlloc, ReceiveFromProcessThreadHandle\n");
				return -1;
			}

			if (!ReadFile(lphPipesHandles[0], lpsReceivingMessage, dwReceivingMessageSize, &dwRead, NULL))
			{
				printf_s("Problem with ReadFile. last error: %d\n", GetLastError());
				return -1;
			}

			lpsDataToSend = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwDatatoSendSize);
			if (lpsDataToSend == NULL)
			{
				printf_s("Problem with HeapAlloc, ReceiveFromProcessThreadHandle\n");
				return -1;
			}

			memset(lpsDataToSend, 0, dwDatatoSendSize);

			if (tpParams->bIsPrivate)
			{
				strcat_s(lpsDataToSend, dwDatatoSendSize, lpsUsername);
				strcat_s(lpsDataToSend, dwDatatoSendSize, "-");
			}

			strcat_s(lpsDataToSend, dwDatatoSendSize, tpParams->lpsChatName);
			strcat_s(lpsDataToSend, dwDatatoSendSize, ":");
			strcat_s(lpsDataToSend, dwDatatoSendSize, lpsReceivingMessage);
			if (lpsReadHeader[0] == OP_INCOMING_CHAT_MESSAGE_EXIT && tpParams->bIsPrivate)
			{
				lpsReadHeader[0] = OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT;
			}

			CreateChatMessage(lpsReadHeader[0], dwDatatoSendSize, lpsDataToSend, &sendingMessage);
			SendChatMessage(sokClientSocket, hEncrytionKey, sendingMessage);

			if (lpsDataToSend != NULL)
				HeapFree(GetProcessHeap(), 0, lpsDataToSend);

			if (lpsReceivingMessage != NULL)
				HeapFree(GetProcessHeap(), 0, lpsReceivingMessage);

			dwReceivingMessageSize = 0;

			ResetChatMessage(&sendingMessage);
		}

	} while (lpsReadHeader[0] != OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT && lpsReadHeader[0] != OP_INCOMING_CHAT_MESSAGE_EXIT);

	DeleteHandlesFromList(tpParams->lpsChatName);
	ExitThread(0);
}

BOOL CreateChatProcess(LPSTR lpsProcessTitle, LPSTR lpsChatName, BOOL bIsPrivate)
{
	BOOL bSuccess = FALSE;
	LPSTR lpsPipeName;
	LPSTR lpsCreateProcessExe;
	DWORD dwPipeNameSize;
	DWORD dwCreateProcessExeSize = 0;
	DWORD dwPipeListNameSize = 0;
	HANDLE hReceiveFromProcessThread;
	STARTUPINFOA siStartInfo;
	PROCESS_INFORMATION piProcInfo;
	pipeHandleList_t* lastPipeHandleInList;
	threadParams_t *threadParams;

	lastPipeHandleInList = CreateNewPipeHandlesInList();
	
	dwPipeListNameSize = (DWORD)strlen(lpsChatName) + 1;
	lastPipeHandleInList->lpsPipeName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPipeListNameSize * sizeof(CHAR));
	if (lastPipeHandleInList->lpsPipeName == NULL)
	{
		printf_s("Problem with HeapAlloc, CreateChatProcess\n");
		return FALSE;
	}

	CopyDataString(&(lastPipeHandleInList->lpsPipeName), (DWORD)strlen(lpsChatName), lpsChatName);

	dwPipeNameSize = SIZE_INBOUND_PREFIX + (DWORD)strlen(lpsChatName) + (DWORD)strlen(lpsUsername) + 2;
	lpsPipeName  = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPipeNameSize * sizeof(CHAR));
	if (lpsPipeName == NULL)
	{
		printf_s("Problem with HeapAlloc, CreateChatProcess\n");
		return FALSE;
	}

	strcat_s(lpsPipeName, dwPipeNameSize, "\\\\.\\pipe\\");
	strcat_s(lpsPipeName, dwPipeNameSize, lpsChatName);
	strcat_s(lpsPipeName, dwPipeNameSize, "-");
	strcat_s(lpsPipeName, dwPipeNameSize, lpsUsername);
	strcat_s(lpsPipeName, dwPipeNameSize, "IN");

	lastPipeHandleInList->lphPipeHandles[0] = CreateNamedPipeA(lpsPipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1, BUFFER_SIZE, BUFFER_SIZE, 0, NULL);

	if (lastPipeHandleInList->lphPipeHandles[0] == INVALID_HANDLE_VALUE)
	{
		printf_s("Problem with CreateNamedPipeA, CreateChatProcess. Last error: %d", GetLastError());
		if (lastPipeHandleInList->lpsPipeName)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList->lpsPipeName);
		if (lastPipeHandleInList != NULL)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList);

		return FALSE;
	}

	if (lpsPipeName != NULL)
		HeapFree(GetProcessHeap(), 0, lpsPipeName);

	dwPipeNameSize = SIZE_OUTBOUND_PREFIX + (DWORD)strlen(lpsChatName) + (DWORD)strlen(lpsUsername) + 2;

	lpsPipeName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPipeNameSize * sizeof(CHAR));
	if (lpsPipeName == NULL)
	{
		printf_s("Problem with HeapAlloc, CreateChatProcess\n");
		return FALSE;
	}

	strcat_s(lpsPipeName, dwPipeNameSize, "\\\\.\\pipe\\");
	strcat_s(lpsPipeName, dwPipeNameSize, lpsChatName);
	strcat_s(lpsPipeName, dwPipeNameSize, "-");
	strcat_s(lpsPipeName, dwPipeNameSize, lpsUsername);
	strcat_s(lpsPipeName, dwPipeNameSize, "OUT");

	lastPipeHandleInList->lphPipeHandles[1] = CreateNamedPipeA(lpsPipeName, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1, BUFFER_SIZE, BUFFER_SIZE, 0, NULL);

	if (lastPipeHandleInList->lphPipeHandles[1] == INVALID_HANDLE_VALUE)
	{
		printf_s("Problem with CreateNamedPipeA, CreateChatProcess. Last error: %d", GetLastError());
		if (lastPipeHandleInList->lpsPipeName)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList->lpsPipeName);

		if (lastPipeHandleInList->lphPipeHandles[0] != NULL)
			CloseHandle(lastPipeHandleInList->lphPipeHandles[0]);

		if (lastPipeHandleInList != NULL)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList);

		return FALSE;
	}

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
	siStartInfo.cb = sizeof(STARTUPINFOA);
	siStartInfo.lpTitle = lpsProcessTitle;
	siStartInfo.dwFlags = STARTF_FORCEONFEEDBACK;

	dwCreateProcessExeSize = 72 + (DWORD)strlen(lpsChatName) + (DWORD)strlen(lpsUsername) + 3;

	lpsCreateProcessExe = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCreateProcessExeSize * sizeof(CHAR));
	if (lpsCreateProcessExe == NULL)
	{
		printf_s("Problem with HeapAlloc, CreateChatProcess. Last error: %d", GetLastError());
		if (lastPipeHandleInList->lpsPipeName)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList->lpsPipeName);

		if (lastPipeHandleInList->lphPipeHandles[0] != NULL)
			CloseHandle(lastPipeHandleInList->lphPipeHandles[0]);

		if (lastPipeHandleInList != NULL)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList);

		return FALSE;
	}

	strcat_s(lpsCreateProcessExe, dwCreateProcessExeSize, "C:\\Users\\pc-1\\Desktop\\chat renewd\\ChatClient\\ChatClient\\ChatWindow.exe ");
	strcat_s(lpsCreateProcessExe, dwCreateProcessExeSize, lpsChatName);
	strcat_s(lpsCreateProcessExe, dwCreateProcessExeSize, " ");
	strcat_s(lpsCreateProcessExe, dwCreateProcessExeSize, lpsUsername);

	bSuccess = CreateProcessA(NULL, lpsCreateProcessExe, NULL, NULL, TRUE,
		CREATE_NEW_CONSOLE, NULL, NULL, &siStartInfo, &piProcInfo);

	if (!bSuccess)
	{
		printf_s("Problem with CreateProcessA, CreateChatProcess. Last error: %d\n", GetLastError());
		if (lastPipeHandleInList->lpsPipeName)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList->lpsPipeName);

		if (lastPipeHandleInList->lphPipeHandles[0] != NULL)
			CloseHandle(lastPipeHandleInList->lphPipeHandles[0]);

		if (lastPipeHandleInList != NULL)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList);

		if (lpsCreateProcessExe != NULL)
			HeapFree(GetProcessHeap(), 0, lpsCreateProcessExe);

		return FALSE;
	}

	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);

	ConnectNamedPipe(lastPipeHandleInList->lphPipeHandles[0], NULL);
	ConnectNamedPipe(lastPipeHandleInList->lphPipeHandles[1], NULL);

	threadParams = (threadParams_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(threadParams_t));
	if (threadParams == NULL)
	{
		printf_s("Problem with CreateThread, CreateChatProcess\n");
		return FALSE;
	}

	threadParams->bIsPrivate = bIsPrivate;
	memset(threadParams->lpsChatName, 0, BUFFER_SIZE);
	strcpy_s(threadParams->lpsChatName, BUFFER_SIZE, lpsChatName);

	hReceiveFromProcessThread = CreateThread(NULL, 0, ReceiveFromProcessThreadHandle, (LPVOID)threadParams, 0, NULL);
	if (hReceiveFromProcessThread == NULL)
	{
		printf_s("Problem with CreateThread, CreateChatProcess. Last error: %d\n", GetLastError());
		if (lastPipeHandleInList->lpsPipeName != NULL)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList->lpsPipeName);

		if (lastPipeHandleInList != NULL)
			HeapFree(GetProcessHeap(), 0, lastPipeHandleInList);

		return FALSE;
	}

	CloseHandle(hReceiveFromProcessThread);

	return TRUE;
}

VOID StartNewPrivateChat(chat_message_t receivedMessage)
{
	CHAR lpsProcessTitle[BUFFER_SIZE];

	snprintf(lpsProcessTitle, BUFFER_SIZE, "%s & %s", lpsUsername, receivedMessage.Data);
	if (!CreateChatProcess(lpsProcessTitle, receivedMessage.Data, TRUE))
	{
		printf_s("Problem with CreateChatProcess, StartNewPrivateChat. Last error: %d\n", GetLastError());
	}

	//create two threads for input and output from the process buffer
}

VOID StartNewPublicChat(chat_message_t receivedMessage)
{
	CHAR lpsProcessTitle[BUFFER_SIZE];

	snprintf(lpsProcessTitle, BUFFER_SIZE, "%s", receivedMessage.Data);
	if (!CreateChatProcess(lpsProcessTitle, receivedMessage.Data, FALSE))
	{
		printf_s("Problem with CreateChatProcess, StartNewPrivateChat. Last error: %d\n", GetLastError());
	}

	//create two threads for input and output from the process buffer
}

DWORD AcceptUsernameFromClient(LPSTR * lpsChosenClientName)
{
	*lpsChosenClientName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SIZE_USERNAME);
	printf_s("Enter username: ");
	scanf_s("%s", *lpsChosenClientName, SIZE_USERNAME);

	while (*lpsChosenClientName == "")
	{
		printf_s("No user inserted, try again!");
		scanf_s("%s", *lpsChosenClientName, SIZE_USERNAME);
	}

	return (DWORD) strlen(*lpsChosenClientName);
}

VOID FailedPrivateChatPrint(chat_message_t receivedMessage)
{
	printf_s("---------------------------------\n");
	printf_s("%s", receivedMessage.Data);
	printf_s("---------------------------------\n");
}

VOID IncomingChatMessageHandle(chat_message_t receivedMessage)
{
	LPHANDLE lphPipeHandles = NULL;
	DWORD dwWritten;
	DWORD dwDataSize = GetDataSizeFromMessage(receivedMessage);
	DWORD dwChatNameSize = IndexUntilDelim(':', receivedMessage.Data, dwDataSize);
	CHAR* cChatData = NULL;
	CHAR* cChatRoomName = strtok_s(receivedMessage.Data, ":", &cChatData);
	CHAR* cPrivateChatRoomName = NULL;
	CHAR* cChatPartyIfPrivate = NULL;
	BOOL bIsChatPrivate = FALSE;
	DWORD dwSendMessageSize = 0;
	CHAR lpsChatMessageBuffer[BUFFER_SIZE] = "";
	DWORD dwPrivateNoteLocation = IndexUntilDelim('-', receivedMessage.Data, dwDataSize);

	if (cChatRoomName == NULL)
	{
		printf_s("Problem with strtok_s, OutcomingChatMessageHandle\n");
		return;
	}

	if (dwPrivateNoteLocation < dwChatNameSize)
	{
		bIsChatPrivate = TRUE;
		cPrivateChatRoomName = strtok_s(receivedMessage.Data, "-", &cChatPartyIfPrivate);
	}

	if (bIsChatPrivate)
	{
		lphPipeHandles = GetHandlesByName(cPrivateChatRoomName);
		cChatRoomName = cPrivateChatRoomName;
		if (lphPipeHandles == NULL)
		{
			lphPipeHandles = GetHandlesByName(cChatPartyIfPrivate);
			cChatRoomName = cChatPartyIfPrivate;
		}
	}
	else
		lphPipeHandles = GetHandlesByName(cChatRoomName);
	
	dwSendMessageSize = dwDataSize - dwChatNameSize - 1;

	receivedMessage.Header[1] = dwSendMessageSize & 0xff;
	receivedMessage.Header[2] = dwSendMessageSize >> 8;

	strcat_s(lpsChatMessageBuffer, dwSendMessageSize, cChatData);

	WriteFile(lphPipeHandles[1], &receivedMessage.Header, HEADER_SIZE, &dwWritten, NULL);
	WriteFile(lphPipeHandles[1], &lpsChatMessageBuffer, dwSendMessageSize, &dwWritten, NULL);
	
	//if (receivedMessage.Header[0] == OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT)
	//{
		//DeleteHandlesFromList(cChatRoomName);
	//}
}

DWORD WINAPI ReceivingThreadHandle(LPVOID lpParam)
{
	chat_message_t receivingMessage;

	while (ReceiveChatMessage(sokClientSocket, hEncrytionKey, &receivingMessage) == 0)
	{
		switch (receivingMessage.Header[0])
		{
		case OP_REPLY_CLIENT_LIST:
			ClientListPrintHandle(receivingMessage);
			break;

		case OP_SUCCESS_REPLY_PRIVATE_CHAT:
			StartNewPrivateChat(receivingMessage);
			break;

		case OP_SUCCESS_REPLY_PUBLIC_CHAT:
			StartNewPublicChat(receivingMessage);
			break;

		case OP_FAILED_REPLY_PRIVATE_CHAT:
			FailedPrivateChatPrint(receivingMessage);
			break;

		case OP_FAILED_REPLY_PUBLIC_CHAT:
			FailedPrivateChatPrint(receivingMessage);
			break;

		case OP_INCOMING_CHAT_MESSAGE:
			IncomingChatMessageHandle(receivingMessage);
			break;

		case OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT:
			IncomingChatMessageHandle(receivingMessage);
			break;

		case OP_INCOMING_CHAT_MESSAGE_EXIT:
			IncomingChatMessageHandle(receivingMessage);
			break;

		case OP_REPLY_CHAT_ROOMS_LIST:
			ChatRoomListPrintHandle(receivingMessage);
			break;

		}

		ResetChatMessage(&receivingMessage);
	}

	printf_s("Problem with RecieveChatMessage\n");
	ExitThread(0);
}

DWORD WINAPI SendingThreadHandle(LPVOID lpParam)
{
	DWORD dwUserChoice = 1;
	DWORD dwSendMessageSize = 0;
	CHAR lpsSendMessage[SIZE_USERNAME] = "";
	CHAR lpsMegaphoneMessage[BUFFER_SIZE] = "";
	chat_message_t sendingMessage;

	while (dwUserChoice > 0)
	{
		dwUserChoice = OptionsMenu();
		if (dwUserChoice == OP_REQUEST_PRIVATE_CHAT || dwUserChoice == OP_REQUEST_PUBLIC_CHAT ||
			dwUserChoice == OP_REQUEST_JOIN_PUBLIC_CHAT || dwUserChoice == OP_MEGAPHONE || dwUserChoice == OP_ADMIN_DELETE_CHAT)
		{
			if (dwUserChoice == OP_REQUEST_PUBLIC_CHAT || dwUserChoice == OP_REQUEST_JOIN_PUBLIC_CHAT || dwUserChoice == OP_ADMIN_DELETE_CHAT)
			{
				printf_s("Enter chat room name: ");
				if (dwUserChoice == OP_ADMIN_DELETE_CHAT)
					printf_s("(for private chat enter \"name1-name2\") ");
			}
			else if (dwUserChoice == OP_REQUEST_PRIVATE_CHAT)
				printf_s("Enter username: ");
			else if (dwUserChoice == OP_MEGAPHONE)
			{
				printf_s("Enter message to all chats: ");
				scanf_s("%s" ,lpsMegaphoneMessage, BUFFER_SIZE);
			}

			if (dwUserChoice != OP_MEGAPHONE)
			{
				scanf_s("%s", lpsSendMessage, SIZE_USERNAME);

				if (!strcmp(lpsSendMessage, "\n") || lpsSendMessage == "")
				{
					printf_s("No user inserted, try again!\n");
					memset(lpsSendMessage, 0, SIZE_USERNAME);
					memset(lpsMegaphoneMessage, 0, BUFFER_SIZE);
					continue;
				}
			}
			
			dwSendMessageSize = (DWORD)strlen(lpsSendMessage);
		}

		if (dwUserChoice != OP_MEGAPHONE)
			CreateChatMessage(dwUserChoice, dwSendMessageSize, lpsSendMessage, &sendingMessage);
		else
		{
			if (strcmp(lpsMegaphoneMessage, "\n") != 0)
				CreateChatMessage(dwUserChoice, (DWORD)strlen(lpsMegaphoneMessage), lpsMegaphoneMessage, &sendingMessage);
			else
			{
				printf_s("No input inserted\n");
				dwSendMessageSize = 0;
				memset(lpsSendMessage, 0, SIZE_USERNAME);
				memset(lpsMegaphoneMessage, 0, BUFFER_SIZE);
				continue;
			}
		}

		if (SendChatMessage(sokClientSocket, hEncrytionKey, sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage, SendingThreadHandle\n");
		}

		dwSendMessageSize = 0;
		memset(lpsSendMessage, 0, SIZE_USERNAME);
		memset(lpsMegaphoneMessage, 0, BUFFER_SIZE);
	}

	ExitThread(0);
}

VOID StartChatRoutine()
{
	DWORD bLoginSuccess;
	HANDLE hSendRecvThreads[2];

	bLoginSuccess = Login();
	while (bLoginSuccess)
	{
		printf("Login failed! Try again\n");
		bLoginSuccess = Login();
	}

	hSendRecvThreads[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendingThreadHandle, NULL, 0, NULL);
	hSendRecvThreads[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReceivingThreadHandle, NULL, 0, NULL);


	WaitForMultipleObjects(2, hSendRecvThreads, FALSE, INFINITE);

	if (hSendRecvThreads[0] != NULL)
		CloseHandle(hSendRecvThreads[0]);

	if (hSendRecvThreads[1] != NULL)
		CloseHandle(hSendRecvThreads[1]);

	if (sokClientSocket != 0)
		closesocket(sokClientSocket);

	if (hAESAlg != NULL)
		BCryptCloseAlgorithmProvider(hAESAlg, 0);

	if (hEncrytionKey != NULL)
		BCryptDestroyKey(hEncrytionKey);

	if (pbKeyObject != NULL)
		HeapFree(GetProcessHeap(), 0, pbKeyObject);

	ReleasePipeHandlesList(pipeHandlesListHead);

	WSACleanup();
}

void main()
{
	/*
	HANDLE hP1, hP2;

	STARTUPINFOA siStartInfo;
	PROCESS_INFORMATION piProcInfo;
	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
	siStartInfo.cb = sizeof(STARTUPINFOA);
	siStartInfo.lpTitle = "aaa";
	siStartInfo.dwFlags = STARTF_FORCEONFEEDBACK;

	LPSTR s1 = "\\\\.\\pipe\\sIN";
	LPSTR s2 = "\\\\.\\pipe\\sOUT";

	hP1 = CreateNamedPipeA(s1, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1, BUFFER_SIZE, BUFFER_SIZE, 0, NULL);

	hP2 = CreateNamedPipeA(s2, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1, BUFFER_SIZE, BUFFER_SIZE, 0, NULL);

	SetHandleInformation(hP1, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(hP2, HANDLE_FLAG_INHERIT, 0);

	LPSTR lpstry = "C:\\Users\\pc-1\\Documents\\Training\\chat\\ChatClient\\ChatWindow.exe s ssss";

	 CreateProcessA(NULL, lpstry, NULL, NULL, TRUE,	CREATE_NEW_CONSOLE, NULL, NULL, &siStartInfo, &piProcInfo);
	 CloseHandle(piProcInfo.hProcess);
	 CloseHandle(piProcInfo.hThread);

	 ConnectNamedPipe(hP1, NULL);
	 ConnectNamedPipe(hP2, NULL);
	 */

	StartChatRoutine();
}