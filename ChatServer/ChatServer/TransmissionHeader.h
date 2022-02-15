#ifndef TRANSMISSION_H_
#define TRANSMISSION_H_

#include <winsock2.h>
#include <stdio.h>

#define HEADER_SIZE 3

typedef struct {
	CHAR Header[HEADER_SIZE];
	LPSTR Data;
} chat_message_t;

VOID CopyDataString(LPSTR* lpsDest, DWORD dwDestSize, LPSTR lpsSource);
DWORD CreateChatMessage(DWORD dwOpCode, DWORD dwDataSize, LPSTR lpsData, chat_message_t* chatMessage);
DWORD GetDataSizeFromMessage(chat_message_t chatMessage);
VOID ResetChatMessage(chat_message_t* messageToReset);

VOID ResetChatMessage(chat_message_t* messageToReset)
{
	messageToReset->Header[0] = 0;
	messageToReset->Header[1] = 0;
	messageToReset->Header[2] = 0;

	if (messageToReset->Data != NULL)
	{
		HeapFree(GetProcessHeap(), 0, messageToReset->Data);
	}
}

VOID CopyDataString(LPSTR* lpsDest, DWORD dwDestSize, LPSTR lpsSource)
{
	for (DWORD dwIter = 0; dwIter < dwDestSize; dwIter++)
		(*lpsDest)[dwIter] = lpsSource[dwIter];
}

// dwRoomNumber is for the chat message, 0 if just a regular message
DWORD CreateChatMessage(DWORD dwOpCode, DWORD dwDataSize, LPSTR lpsData, chat_message_t* chatMessage)
{
	chatMessage->Header[0] = dwOpCode;
	chatMessage->Header[1] = dwDataSize & 0xff;
	chatMessage->Header[2] = dwDataSize >> 8;

	if (dwDataSize != 0)
	{
		chatMessage->Data = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDataSize + 1);
		if (chatMessage->Data == NULL)
		{
			printf_s("Problem with CreateChatMessage\n");
			return -1;
		}

		CopyDataString(&(chatMessage->Data), dwDataSize, lpsData);
	}

	return 0;
}

DWORD GetDataSizeFromMessage(chat_message_t chatMessage)
{
	return chatMessage.Header[1] + (chatMessage.Header[2] << 8);
}

#endif