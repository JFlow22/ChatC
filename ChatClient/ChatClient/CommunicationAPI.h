#ifndef COMMUNICATIONAPI_H_
#define COMMUNICATIONAPI_H_

#include "Encryption.h"
#include "TransmissionHeader.h"

// sendMessage will contain the size of the plaintext
// the function will send the encrypted message size
DWORD SendChatMessage(SOCKET sokSendingSocket, BCRYPT_KEY_HANDLE hEncryptionKey, chat_message_t sendMessage) 
{
	DWORD dwMessageSize = 0;
	DWORD dwEncryptedMessageSize = 0;
	LPSTR lpsSendingMessage = NULL;
	PBYTE pbEncryptedMessage = NULL;
	// reminder: add name to start of data string
	
	dwMessageSize = sendMessage.Header[1] + (sendMessage.Header[2] << 8);

	if (hEncryptionKey != NULL)
	{
		if (EncryptMessage(hEncryptionKey, (PBYTE)(sendMessage.Data), dwMessageSize, &pbEncryptedMessage,
			&dwEncryptedMessageSize) != 0)
		{
			printf_s("Problem with EncryptMessage, SendChatMessage\n");
			return -1;
		}
		sendMessage.Header[1] = dwEncryptedMessageSize & 0xff;
		sendMessage.Header[2] = dwEncryptedMessageSize >> 8;

		sendMessage.Data = (CHAR*)pbEncryptedMessage;
		dwMessageSize = dwEncryptedMessageSize;
	}

	if (send(sokSendingSocket, sendMessage.Header, HEADER_SIZE, 0) < 0)
	{
		printf("Send failed, SendChatMessage\n");
		if (pbEncryptedMessage)
			HeapFree(GetProcessHeap(), 0, pbEncryptedMessage);

		return -1;
	}
	
	if (send(sokSendingSocket, sendMessage.Data, dwMessageSize, 0) < 0)
	{
		printf("Send failed, SendChatMessage\n");
		if (pbEncryptedMessage)
			HeapFree(GetProcessHeap(), 0, pbEncryptedMessage);

		return -1;
	}

	if (pbEncryptedMessage)
		HeapFree(GetProcessHeap(), 0, pbEncryptedMessage);

	return 0;
}

// receiveMessage will contain the size of the plaintext
// the function will receive the encrypted message size
DWORD ReceiveChatMessage(SOCKET sokReciveingSocket, BCRYPT_KEY_HANDLE hDecryptionKey, chat_message_t* receiveMessage)
{
	DWORD dwMessageSize;
	DWORD dwMessageReciveSize = 0;
	DWORD dwDecryptedMessageSize = 0;
	PBYTE pbDecryptedMessage = NULL;

	(*receiveMessage).Data = NULL;

	if ((dwMessageReciveSize = recv(sokReciveingSocket, (*receiveMessage).Header, HEADER_SIZE, 0)) == SOCKET_ERROR)
	{
		printf_s("recv (ReceiveChatMessage) failed, last error:  %d\n", WSAGetLastError());
		return -1;
	}

	if ((*receiveMessage).Header[1] == 0 && (*receiveMessage).Header[2] == 0 && hDecryptionKey == NULL)
	{
		(*receiveMessage).Data = NULL;
	}
	else
	{
		dwMessageSize = (*receiveMessage).Header[1] + ((*receiveMessage).Header[2] << 8);
		(*receiveMessage).Data = (CHAR*)HeapAlloc(GetProcessHeap(), 0, sizeof(CHAR) * dwMessageSize);

		if ((*receiveMessage).Data == NULL)
		{
			printf_s("HeapAlloc Failed!\n");
			return -1;
		}

		if ((dwMessageReciveSize = recv(sokReciveingSocket, (*receiveMessage).Data, dwMessageSize, 0)) == SOCKET_ERROR)
		{
			printf("recv (ReceiveChatMessage) failed, last error:  %d\n", WSAGetLastError());
			if ((*receiveMessage).Data)
				HeapFree(GetProcessHeap(), 0, (*receiveMessage).Data);
			return -1;
		}

		if (hDecryptionKey != NULL)
		{
			if (DecryptMessage(hDecryptionKey, (PBYTE)((*receiveMessage).Data), dwMessageSize,
				&pbDecryptedMessage, &dwDecryptedMessageSize) != 0)
			{
				printf_s("Problem with DecryptMessage, ReceiveChatMessage\n");
				if ((*receiveMessage).Data)
					HeapFree(GetProcessHeap(), 0, (*receiveMessage).Data);
				return -1;
			}

			(*receiveMessage).Header[1] = dwDecryptedMessageSize & 0xff;
			(*receiveMessage).Header[2] = dwDecryptedMessageSize >> 8;

			if ((*receiveMessage).Data)
				HeapFree(GetProcessHeap(), 0, (*receiveMessage).Data);

			(*receiveMessage).Data = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwDecryptedMessageSize);
			if ((*receiveMessage).Data == NULL)
			{
				printf_s("HeapAlloc Failed!\n");
				if (pbDecryptedMessage)
					HeapFree(GetProcessHeap(), 0, pbDecryptedMessage);

				return -1;
			}

			CopyDataString(&((*receiveMessage).Data), dwDecryptedMessageSize, (CHAR*)pbDecryptedMessage);
		}

		if (pbDecryptedMessage)
			HeapFree(GetProcessHeap(), 0, pbDecryptedMessage);
	}

	return 0;
}

#endif // !COMMUNICATIONAPI_H_
