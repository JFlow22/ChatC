#include <winsock2.h>
#include <stdio.h>
#include "TransmissionHeader.h"

#define BUFFER_SIZE 4096
#define OP_INCOMING_CHAT_MESSAGE 9
#define	OP_INCOMING_CHAT_MESSAGE_EXIT 90
#define OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT 99
#define SIZE_INBOUND_PREFIX 12
#define SIZE_OUTBOUND_PREFIX 13

CHAR lpsUsername[BUFFER_SIZE];

HANDLE OpenPipe(LPSTR lpsName, DWORD dwOpenMode)
{
	HANDLE hPipe;
	DWORD dwLastError;

	hPipe = CreateFileA(lpsName, dwOpenMode, 0, NULL, OPEN_EXISTING, 0, NULL);

	while (hPipe == INVALID_HANDLE_VALUE)
	{
		dwLastError = GetLastError();
		if (dwLastError != ERROR_PIPE_BUSY)
		{
			printf_s("Problem in OpenPipe, last error: %d\n", dwLastError);
			return INVALID_HANDLE_VALUE;
		}

		if (!WaitNamedPipeA(lpsName, 5000))
		{
			printf_s("Cannot open pipe, timed out\n");
			return INVALID_HANDLE_VALUE;
		}

		hPipe = CreateFileA(lpsName, dwOpenMode, 0, NULL, OPEN_EXISTING, 0, NULL);
	}

	return hPipe;
}

DWORD OpenBothPipes(LPSTR lpsName, LPHANDLE lphPipeInstream, LPHANDLE lphPipeOutstream)
{
	LPSTR lpsPipeName;
	DWORD dwPipeNameSize;
	
	dwPipeNameSize = SIZE_INBOUND_PREFIX + (DWORD)strlen(lpsName) + 1;
	lpsPipeName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPipeNameSize * sizeof(CHAR));
	if (lpsPipeName == NULL)
	{
		printf_s("Problem with HeapAlloc, CreateChatProcess\n");
		return FALSE;
	}

	strcat_s(lpsPipeName, dwPipeNameSize, "\\\\.\\pipe\\");
	strcat_s(lpsPipeName, dwPipeNameSize, lpsName);
	strcat_s(lpsPipeName, dwPipeNameSize, "IN");

	*lphPipeInstream = OpenPipe(lpsPipeName, GENERIC_WRITE);

	if (*lphPipeInstream == INVALID_HANDLE_VALUE)
	{
		printf_s("Problem with OpenPipe, OpenBothPipes. last error: %d\n", GetLastError());
		return -1;
	}

	if (lpsPipeName != NULL)
		HeapFree(GetProcessHeap(), 0, lpsPipeName);

	dwPipeNameSize = SIZE_OUTBOUND_PREFIX + (DWORD)strlen(lpsName) + 1;
	lpsPipeName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPipeNameSize * sizeof(CHAR));
	if (lpsPipeName == NULL)
	{
		printf_s("Problem with HeapAlloc, CreateChatProcess\n");
		return FALSE;
	}

	strcat_s(lpsPipeName, dwPipeNameSize, "\\\\.\\pipe\\");
	strcat_s(lpsPipeName, dwPipeNameSize, lpsName);
	strcat_s(lpsPipeName, dwPipeNameSize, "OUT");

	*lphPipeOutstream = OpenPipe(lpsPipeName, GENERIC_READ);
	if (*lphPipeOutstream == INVALID_HANDLE_VALUE)
	{
		printf_s("Problem with OpenPipe, OpenBothPipes. last error: %d\n", GetLastError());
		return -1;
	}

	if (lpsPipeName != NULL)
		HeapFree(GetProcessHeap(), 0, lpsPipeName);

	return 0;
}

VOID WINAPI ReceiveMessageHandle(LPVOID lphPipe)
{
	DWORD dwRead;
	chat_message_t receivingMessage;
	CHAR lpsReadHeader[HEADER_SIZE];
	DWORD dwReadMessageSize;
	LPSTR lpsReceivingMessage;

	do {
		if (!ReadFile((HANDLE)lphPipe, &lpsReadHeader, HEADER_SIZE, &dwRead, NULL))
		{
			printf_s("Problem with ReadFile. last error: %d\n", GetLastError());
			ExitThread(1);
		}
		printf_s("lpsReadHeader: %s\n", lpsReadHeader);
		if (lpsReadHeader[0] == OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT)
			break;
		else
		{
			dwReadMessageSize = lpsReadHeader[1] + (lpsReadHeader[2] << 8) + 1;
			lpsReceivingMessage = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwReadMessageSize);
			if (lpsReceivingMessage == NULL)
			{
				printf_s("Problem with HeapAlloc, ReceiveMessageHandle\n");
				ExitThread(1);
			}

			if (!ReadFile((HANDLE)lphPipe, &lpsReceivingMessage, dwReadMessageSize, &dwRead, NULL))
			{
				printf_s("Problem with ReadFile. last error: %d\n", GetLastError());
				ExitThread(1);
			}

			printf_s("%s\n", lpsReceivingMessage);
		}

		if (lpsReceivingMessage != NULL)
			HeapFree(GetProcessHeap(), 0, lpsReceivingMessage);
		
		dwReadMessageSize = 0;


	} while (receivingMessage.Header[0] != OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT);

	printf_s("Admin left the chat. exiting!\n");
	
	ExitThread(0);
}

VOID WINAPI SendMessagesHandle(LPVOID lpParams)
{
	DWORD dwWritten;
	DWORD dwMessageToSendSize;
	CHAR lpsWriteHeader[HEADER_SIZE];
	CHAR lpsChatMessageBuffer[BUFFER_SIZE] = "";
	CHAR lpsMessageToSend[BUFFER_SIZE] = "";

	do
	{
		memset(lpsChatMessageBuffer, 0, BUFFER_SIZE);
		memset(lpsMessageToSend, 0, BUFFER_SIZE);
		scanf_s("%s", lpsChatMessageBuffer, BUFFER_SIZE);
		if (!strcmp(lpsChatMessageBuffer, "exit"))
			break;

		snprintf(lpsMessageToSend, BUFFER_SIZE, "%s:%s\0", lpsUsername, lpsChatMessageBuffer);
		dwMessageToSendSize = (DWORD)strlen(lpsMessageToSend);
		

		lpsWriteHeader[0] = OP_INCOMING_CHAT_MESSAGE;
		lpsWriteHeader[1] = dwMessageToSendSize & 0xff;
		lpsWriteHeader[2] = dwMessageToSendSize >> 8;

		WriteFile((HANDLE)lpParams, &lpsWriteHeader, HEADER_SIZE, &dwWritten, NULL);
		WriteFile((HANDLE)lpParams, &lpsMessageToSend, dwMessageToSendSize, &dwWritten, NULL);


	} while (strcmp(lpsChatMessageBuffer, "exit") != 0);


	memset(lpsMessageToSend, 0, BUFFER_SIZE);

	snprintf(lpsMessageToSend, BUFFER_SIZE, "%s:exit", lpsUsername);

	dwMessageToSendSize = (DWORD)strlen(lpsMessageToSend);
	lpsWriteHeader[0] = OP_INCOMING_CHAT_MESSAGE_EXIT;
	lpsWriteHeader[1] = 0;
	lpsWriteHeader[2] = 0;

	WriteFile((HANDLE)lpParams, &lpsWriteHeader, HEADER_SIZE, &dwWritten, NULL);
	WriteFile((HANDLE)lpParams, &lpsMessageToSend, dwMessageToSendSize, &dwWritten, NULL);

	ExitThread(0);
}

void main(int argc, char** argv)
{
	DWORD dwWritten;
	HANDLE hPipeInStream;
	HANDLE hPipeOutStream;
	HANDLE hThreadsIO[2];
	chat_message_t sendMessage;

	memset(lpsUsername, 0, BUFFER_SIZE);
	strcpy_s(lpsUsername, BUFFER_SIZE, argv[2]);

	printf_s("Welcome to %s chat %s!\n", argv[1], lpsUsername);
	
	if (OpenBothPipes(argv[1], &hPipeInStream, &hPipeOutStream) != 0)
	{
		printf_s("Problem with OpenBothPipes, main\n");
		return;
	}

	hThreadsIO[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendMessagesHandle, (LPVOID)hPipeInStream, 0, NULL);
	if (hThreadsIO[0] == NULL)
	{
		printf_s("Problem with CreateThread, main. last error: %d\n", GetLastError());
		CreateChatMessage(OP_INCOMING_CHAT_MESSAGE_EXIT, 2, "p", &sendMessage);
		WriteFile(hPipeInStream, &sendMessage, sizeof(sendMessage), &dwWritten, NULL);
		CloseHandle(hPipeInStream);
		CloseHandle(hPipeOutStream);

		return;
	}

	hThreadsIO[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReceiveMessageHandle, (LPVOID)hPipeOutStream, 0, NULL);
	if (hThreadsIO[1] == NULL)
	{
		printf_s("Problem with CreateThread, main. last error: %d\n", GetLastError());
		TerminateThread(hThreadsIO[0], 1);
		CloseHandle(hThreadsIO[0]);
		CreateChatMessage(OP_INCOMING_CHAT_MESSAGE_EXIT, 2, "p", &sendMessage);
		WriteFile(hPipeInStream, &sendMessage, sizeof(sendMessage), &dwWritten, NULL);
		CloseHandle(hPipeInStream);
		CloseHandle(hPipeOutStream);

		return;
	}


	WaitForMultipleObjects(2, hThreadsIO, FALSE, INFINITE);

	while (TRUE)
	{
		printf("loop");
	}
	TerminateThread(hThreadsIO[0], 0);
	TerminateThread(hThreadsIO[1], 0);
	CloseHandle(hThreadsIO[0]);
	CloseHandle(hThreadsIO[1]);

	CloseHandle(hPipeInStream);
	CloseHandle(hPipeOutStream);
}