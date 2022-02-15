#include <stdio.h>
#include <stdlib.h>
#include "ChatServer/TransmissionHeader.h"
#include "ChatServer/ServerHeader.h"
#include "ChatServer/Encryption.h"
#include "ChatServer/OpCodeList.h"
#include "ChatServer/CommunicationAPI.h"
#include "ChatServer/Lists.h"

#pragma comment(lib,"ws2_32.lib")
 
DWORD InitWinsock(WSADATA* wsa);
DWORD CreateAcceptingSocket(SOCKET* pAcceptingSocket);
DWORD ExportClientKeyBlob(BCRYPT_KEY_HANDLE hCommsKey, DWORD* dwBlobSize, PBYTE* pbBlob);
DWORD ClientLogin(client_t* newClient, chat_message_t receiveMessage);
DWORD CreateNewChatRoom(LPSTR lpsClientStarting, LPSTR lpsChatRoomName, DWORD dwChatRoomNameSize);
DWORD DeleteChatRoomFromList(LPSTR lpsChatRoomName);
DWORD DeleteClientFromList(LPSTR lpsClientName);
DWORD IndexUntilDelim(CHAR cDelim, LPSTR lpsStringToSearch, DWORD dwStringSize);
DWORD CountAllChatRoomNameSizes();
DWORD AllChatRoomNamesString(LPSTR* lpsChatRoomNamesString);
DWORD JoinChatRoom(LPSTR lpsRequestingClient, LPSTR lpsChatRoomName);
DWORD CheckNewClientName(SOCKET sokNewClientSocket, chat_message_t* receivedMessage);
DWORD WINAPI ClientThreadHandle(LPVOID lpParam);
DWORD FindOpenThread(HANDLE* hThreadsList);
DWORD AcceptNewClient(SOCKET clientSocket);
DWORD AllClientsNamesString(LPSTR lpsAskingClient, LPSTR* lpsClientsNames);
DWORD CountAllNamesSizes(LPSTR lpsAskingClient);
VOID SendClientListHandle(LPSTR lpsClientName);
VOID DeleteChatRoom(chatRoomList_t* chatRoomToDelete);
VOID DeleteClient(clientList_t* clientToDelete);
VOID StartNewPrivateChat(LPSTR lpsClientIDStarting, LPSTR lpsClientIDAccepting);
VOID SendExitToAllParticipants(chatRoom_t* chatRoomToClose);
VOID DeleteClientFromChatRoom(LPSTR lpsClientName, LPSTR lpsChatRoomName);
VOID NewPrivateChatHandle(LPSTR lpsClientName, chat_message_t receivedMessage);
VOID OutcomingChatMessageHandle(chat_message_t receivingMessage, DWORD dwOpCode, LPSTR lpsReceivingClient);
VOID SendChatRoomListHandle(LPSTR lpsCurrentClientName);
VOID StartNewPublicChat(LPSTR lpsClientName, LPSTR lpsChatRoomName);
VOID NewPublicChatHandle(LPSTR lpsRequestingClient, chat_message_t receivedMessage);
VOID JoinPublicChatHandle(LPSTR lpsRequestingClient, chat_message_t receivedMessage);
BOOL IsClientExist(LPSTR lpsClientName);
BOOL IsChatRoomExist(LPSTR lpsChatRoomName);
BOOL IsClientInChatRoom(LPSTR lpsClientName, LPSTR lpsChatRoomName);
BOOL CheckPrivateChatExistence(LPSTR lpsFirstName, LPSTR lpsSecondName);
BOOL IsClientInPartyList(client_t** chatParticipants, DWORD dwChatPartySize, LPSTR lpsClientName);
BOOL IsClientAdmin(LPSTR lpsClientName);

DWORD InitWinsock(WSADATA *wsa)
{
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2), wsa) != 0)
	{
		printf("Failed. Error Code : %d",WSAGetLastError());
		return 1;
	}

	printf("Initialised.\n");
	return 0;
}

DWORD CreateAcceptingSocket(SOCKET *pAcceptingSocket) // creates and binds the socket
{
	struct sockaddr_in server;

	if((*pAcceptingSocket = socket(AF_INET , SOCK_STREAM , 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d" , WSAGetLastError());
		return 1;
	}

	printf("Socket created\n");
	server.sin_family = AF_INET;
	InetPtonA(AF_INET, SERVER_IP_ADDR, &(server.sin_addr.s_addr));
	server.sin_port = htons(8888);

	if(bind(*pAcceptingSocket ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR)
	{
		printf("Bind failed with error code : %d" , WSAGetLastError());
		return 1;
	}

	printf("Bind done\n");
	return 0;
}

DWORD ExportClientKeyBlob(BCRYPT_KEY_HANDLE hCommsKey, DWORD *dwBlobSize, PBYTE *pbBlob)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status = BCryptExportKey(hCommsKey, NULL, BCRYPT_KEY_DATA_BLOB,
		NULL, 0, dwBlobSize, 0)))
	{
		printf("**** Error 0x%x returned by BCryptExportKey\n", status);
		return -1;
	}

	*pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *dwBlobSize);
	if (pbBlob == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	if (!NT_SUCCESS(status = BCryptExportKey(hCommsKey, NULL, BCRYPT_KEY_DATA_BLOB,
		*pbBlob, *dwBlobSize, dwBlobSize, 0)))
	{
		printf("Problem with BCryptExportKey, error: 0x%x\n", status);
		return -1;
	}

	return 0;
}

DWORD ClientLogin(client_t *newClient, chat_message_t receiveMessage)
{
	DWORD	dwOpCode				= 0;
	DWORD	dwClientNameSize		= 0;
	DWORD	dwBlobSize				= 0;
	LPSTR	lpsClientName			= NULL;
	PBYTE	pbBlob					= NULL;
	chat_message_t sendMessage;
	chat_message_t receivingMessage;
	BCRYPT_KEY_HANDLE hPublicKey = 0;
	LPSTR pbCipherText = NULL;
	DWORD cbCipherText = 0;

	dwClientNameSize = GetDataSizeFromMessage(receiveMessage) + 1;
	newClient->lpsClientName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,	sizeof(CHAR) * dwClientNameSize);
	if (newClient->lpsClientName == NULL)
	{
		printf("HeapAlloc failed, ClientLogin\n");
		return -1;
	}

	CreateChatMessage(OP_REPLY_ASYMMETRIC_KEY, 0, NULL, &sendMessage);

	if (SendChatMessage(newClient->clientSocket, NULL, sendMessage) != 0)
	{
		printf_s("Send failed, Login\n");
		return -1;
	}

	if (ReceiveChatMessage(newClient->clientSocket, NULL, &receivingMessage) != 0)
	{
		printf_s("Receive failed, Login\n");
		return -1;
	}
	
	GetRSAHandle();
	ImportPublicBlob(receivingMessage.Data, GetDataSizeFromMessage(receivingMessage), &hPublicKey);

	CopyDataString(&(newClient->lpsClientName), GetDataSizeFromMessage(receiveMessage), receiveMessage.Data);
	CreateAesKey(&(newClient->hCommsKey), &(newClient->cbKeyObject), &(newClient->pbKeyObject));

	if (ExportClientKeyBlob(newClient->hCommsKey, &dwBlobSize, &pbBlob))
	{
		printf_s("Problem with ExportClientKeyBlob, ClientLogin\n");
		goto Cleanup;
	}

	if (EncryptSymmetricKeyBlob(hPublicKey, pbBlob, dwBlobSize, &pbCipherText, &cbCipherText) != 0)
	{
		printf_s("Problem with EncryptSymmetricKeyBlob, ClientLogin\n");
		goto Cleanup;
	}

	if (CreateChatMessage(OP_LOGIN_KEY_REPLY, cbCipherText, (CHAR*)pbCipherText, &sendMessage) != 0)
	{
		printf_s("Problem with CreateChatMessage, ClientLogin\n");
		return -1;
	}

	if (SendChatMessage(newClient->clientSocket, NULL, sendMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, ClientLogin\n");
		goto Cleanup;
	}
	
	ResetChatMessage(&sendMessage);

	if (IsClientAdmin(newClient->lpsClientName))
	{
		if (CreateChatMessage(OP_LOGIN_AS_ADMIN, 0, NULL, &sendMessage) != 0)
		{
			printf_s("Problem with CreateChatMessage, ClientLogin\n");
			return -1;
		}
	}
	else
	{
		if (CreateChatMessage(OP_LOGIN_AS_NORMAL, 0, NULL, &sendMessage) != 0)
		{
			printf_s("Problem with CreateChatMessage, ClientLogin\n");
			return -1;
		}
	}

	if (SendChatMessage(newClient->clientSocket, NULL, sendMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, ClientLogin\n");
		goto Cleanup;
	}

	ResetChatMessage(&receiveMessage);
	if (hPublicKey)
		BCryptDestroyKey(hPublicKey);
	return 0;

Cleanup:
	if (pbBlob)
		HeapFree(GetProcessHeap(), 0, pbBlob);

	if (newClient->lpsClientName)
		HeapFree(GetProcessHeap(), 0, newClient->lpsClientName);

	if (newClient->hCommsKey)
		BCryptDestroyKey(newClient->hCommsKey);

	if (hPublicKey)
		BCryptDestroyKey(hPublicKey);

	return -1;
}

BOOL IsClientAdmin(LPSTR lpsClientName)
{
	for (DWORD dwAdminInList = 0; dwAdminInList < ADMIN_COUNT; dwAdminInList++)
	{
		if (!strcmp(lpsaAdmins[dwAdminInList], lpsClientName))
			return TRUE;
	}

	return FALSE;
}

VOID SendClientListHandle(LPSTR lpsClientName)
{
	LPSTR lpsClientNames = NULL;
	DWORD dwClientNamesSize = 0;
	chat_message_t sendMessage;
	client_t* currentClient = GetClientByName(lpsClientName);

	if ((dwClientNamesSize = AllClientsNamesString(lpsClientName, &lpsClientNames)) < 0)
	{
		printf_s("Problem with AllClientsNamesString, SendClientList\n");
		return;
	}
	else if (dwClientNamesSize == 0)
	{
		dwClientNamesSize = 24;
		lpsClientNames = (CHAR*)HeapAlloc(GetProcessHeap(), 0, dwClientNamesSize * sizeof(CHAR));
		CopyDataString(&lpsClientNames, dwClientNamesSize, "No online users found.\n");
	}

	if (CreateChatMessage(OP_REPLY_CLIENT_LIST, dwClientNamesSize, lpsClientNames, &sendMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, SendClientList\n");
		if (lpsClientNames)
			HeapFree(GetProcessHeap(), 0, lpsClientNames);
		
		return;
	}

	if (SendChatMessage(currentClient->clientSocket, currentClient->hCommsKey, sendMessage) != 0)
	{
		printf_s("Problem with SendChatMessage\n");
		if (lpsClientNames)
			HeapFree(GetProcessHeap(), 0, lpsClientNames);

		ResetChatMessage(&sendMessage);
		return;
	}

	if (lpsClientNames)
		HeapFree(GetProcessHeap(), 0, lpsClientNames);

	ResetChatMessage(&sendMessage);
}

BOOL IsClientExist(LPSTR lpsClientName)
{
	client_t* clientCheck = GetClientByName(lpsClientName);

	if (clientCheck == NULL) return FALSE;

	return TRUE;
}
//Completed
DWORD CreateNewChatRoom(LPSTR lpsClientStarting, LPSTR lpsChatRoomName, DWORD dwChatRoomNameSize)
{
	return AddNewChatRoom(lpsClientStarting, lpsChatRoomName, dwChatRoomNameSize);
}

DWORD DeleteChatRoomFromList(LPSTR lpsChatRoomName)
{
	chatRoomList_t* chatRoomToDelete = NULL;
	chatRoomList_t* chatRoomIter = chatRoomListHead;

	if (chatRoomIter == NULL)
		return -1;

	if (chatRoomIter->nextRoom == NULL)
	{
		if (strcmp(chatRoomIter->chatRoom.lpsChatRoomName, lpsChatRoomName) == 0)
		{
			if (chatRoomIter->chatRoom.lpsChatRoomName != NULL)
				HeapFree(GetProcessHeap(), 0, chatRoomIter->chatRoom.lpsChatRoomName);
			
			if (chatRoomIter->chatRoom.chatParticipants != NULL)
				HeapFree(GetProcessHeap(), 0, chatRoomIter->chatRoom.chatParticipants);

			if (chatRoomIter->chatRoom.lpsAdminClientName != NULL)
				chatRoomIter->chatRoom.lpsAdminClientName = NULL;
			
			HeapFree(GetProcessHeap(), 0, chatRoomIter);

			chatRoomListHead = NULL;
			return 0;
		}

		return -1;
	}

	while (chatRoomIter->nextRoom != NULL)
	{
		if (strcmp(chatRoomIter->nextRoom->chatRoom.lpsChatRoomName, lpsChatRoomName) == 0)
		{
			chatRoomToDelete = chatRoomIter->nextRoom;
			break;
		}

		chatRoomIter = chatRoomIter->nextRoom;
	}

	if (chatRoomToDelete != NULL)
	{
		chatRoomIter->nextRoom = chatRoomToDelete->nextRoom;
		chatRoomToDelete->nextRoom = NULL;

		if (chatRoomToDelete->chatRoom.lpsChatRoomName != NULL)
			HeapFree(GetProcessHeap(), 0, chatRoomToDelete->chatRoom.lpsChatRoomName);

		if (chatRoomToDelete->chatRoom.chatParticipants != NULL)
			HeapFree(GetProcessHeap(), 0, chatRoomToDelete->chatRoom.chatParticipants);

		if (chatRoomToDelete->chatRoom.lpsAdminClientName != NULL)
			chatRoomToDelete->chatRoom.lpsAdminClientName = NULL;

		HeapFree(GetProcessHeap(), 0, chatRoomToDelete);
	}
	return 0;
}

VOID DeleteChatRoom(chatRoomList_t* chatRoomToDelete)
{
	if (chatRoomToDelete == NULL)
		return;

	if (chatRoomToDelete->chatRoom.lpsChatRoomName != NULL)
		HeapFree(GetProcessHeap(), 0, chatRoomToDelete->chatRoom.lpsChatRoomName);

	if (chatRoomToDelete->chatRoom.chatParticipants != NULL)
		HeapFree(GetProcessHeap(), 0, chatRoomToDelete->chatRoom.chatParticipants);

	if (chatRoomToDelete != NULL)
		HeapFree(GetProcessHeap(), 0, chatRoomToDelete);
}

DWORD DeleteClientFromList(LPSTR lpsClientName)
{
	clientList_t* clientToDelete;
	clientList_t* clientIter = clientListHead;

	if (clientIter == NULL)
		return -1;

	if (clientIter->nextClient == NULL)
	{
		if (strcmp(clientIter->ClientData.lpsClientName, lpsClientName) == 0)
		{
			DeleteClient(clientIter);
			return 0;
		}

		return -1;
	}

	while (clientIter->nextClient != NULL)
	{
		if (strcmp(clientIter->nextClient->ClientData.lpsClientName, lpsClientName) == 0)
			break;

		clientIter = clientIter->nextClient;
	}

	clientToDelete = clientIter->nextClient;

	if (clientToDelete != NULL && clientToDelete->nextClient != NULL)
	{
		clientIter->nextClient = clientToDelete->nextClient;
		clientToDelete->nextClient = NULL;
	}

	DeleteClient(clientToDelete);

	return 0;
}

VOID DeleteClient(clientList_t* clientToDelete)
{
	if (clientToDelete->ClientData.clientSocket != 0)
		closesocket(clientToDelete->ClientData.clientSocket);

	if (clientToDelete->ClientData.hCommsKey != NULL)
		BCryptDestroyKey(clientToDelete->ClientData.hCommsKey);

	if (clientToDelete->ClientData.lpsClientName != NULL)
		HeapFree(GetProcessHeap(), 0, clientToDelete->ClientData.lpsClientName);

	if (clientToDelete->ClientData.pbKeyObject != NULL)
		HeapFree(GetProcessHeap(), 0, clientToDelete->ClientData.pbKeyObject);

	if (clientToDelete != NULL)
		HeapFree(GetProcessHeap(), 0, clientToDelete);
}

VOID StartNewPrivateChat(LPSTR lpsClientIDStarting, LPSTR lpsClientIDAccepting)
{
	chat_message_t sendingMessage;
	LPSTR lpsNewChatMessage;
	LPSTR lpsChatRoomName;
	DWORD dwChatRoomNameSize = 0;
	DWORD dwNewChatMessageSize = 25;
	DWORD dwChatRoomID;
	client_t* clientStarting = GetClientByName(lpsClientIDStarting);
	client_t* clientAccepting = GetClientByName(lpsClientIDAccepting);

	dwNewChatMessageSize = (DWORD)strlen(lpsClientIDAccepting) + 1;
	lpsNewChatMessage = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwNewChatMessageSize);
	if (lpsNewChatMessage == NULL)
	{
		printf_s("Problem with HeapAlloc, StartNewPrivateChat\n");
		return;
	}

	CopyDataString(&lpsNewChatMessage, dwNewChatMessageSize, lpsClientIDAccepting);

	if (CreateChatMessage(OP_SUCCESS_REPLY_PRIVATE_CHAT, dwNewChatMessageSize, lpsNewChatMessage, &sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, StartNewPrivateChat\n");
		return;
	}

	if (SendChatMessage(clientStarting->clientSocket, clientStarting->hCommsKey ,sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, StartNewPrivateChat\n");
		ResetChatMessage(&sendingMessage);
		return;
	}

	if (lpsNewChatMessage != NULL)
		HeapFree(GetProcessHeap(), 0, lpsNewChatMessage);

	ResetChatMessage(&sendingMessage);

	dwNewChatMessageSize = (DWORD)strlen(lpsClientIDStarting) + 1;
	lpsNewChatMessage = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwNewChatMessageSize);
	if (lpsNewChatMessage == NULL)
	{
		printf_s("Problem with HeapAlloc, StartNewPrivateChat\n");
		return;
	}

	CopyDataString(&lpsNewChatMessage, dwNewChatMessageSize, lpsClientIDStarting);

	if (CreateChatMessage(OP_SUCCESS_REPLY_PRIVATE_CHAT, dwNewChatMessageSize, lpsNewChatMessage, &sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, StartNewPrivateChat\n");
		return;
	}

	if (SendChatMessage(clientAccepting->clientSocket, clientAccepting->hCommsKey, sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, StartNewPrivateChat\n");
		ResetChatMessage(&sendingMessage);
		return;
	}

	ResetChatMessage(&sendingMessage);
	
	dwChatRoomNameSize = (DWORD)strlen(lpsClientIDStarting) + (DWORD)strlen(lpsClientIDAccepting) + 2;
	lpsChatRoomName = (CHAR*)HeapAlloc(GetProcessHeap(), 0, sizeof(CHAR) * dwChatRoomNameSize);
	snprintf(lpsChatRoomName, dwChatRoomNameSize, "%s-%s\0", lpsClientIDStarting, lpsClientIDAccepting);

	dwChatRoomID = CreateNewChatRoom(lpsClientIDStarting, lpsChatRoomName, dwChatRoomNameSize);

	if (lpsChatRoomName != NULL)
		HeapFree(GetProcessHeap(), 0, lpsChatRoomName);

	if (lpsNewChatMessage != NULL)
		HeapFree(GetProcessHeap(), 0, lpsNewChatMessage);

	AddClientToChatRoom(lpsClientIDAccepting, dwChatRoomID);
	AddClientToChatRoom(lpsClientIDStarting, dwChatRoomID);
}

BOOL IsChatRoomExist(LPSTR lpsChatRoomName)
{
	chatRoom_t* chatRoomCheck = GetChatRoomByName(lpsChatRoomName);

	if (chatRoomCheck == NULL) return FALSE;

	return TRUE;
}

BOOL IsClientInChatRoom(LPSTR lpsClientName, LPSTR lpsChatRoomName)
{
	chatRoom_t* chatRoomToCheck = GetChatRoomByName(lpsChatRoomName);

	if (!strcmp(chatRoomToCheck->lpsAdminClientName, lpsClientName)) return TRUE;

	for (DWORD dwClientInRoom = 0; dwClientInRoom < chatRoomToCheck->dwPartyCounter; dwClientInRoom++)
	{
		if (!strcmp(chatRoomToCheck->chatParticipants[dwClientInRoom]->lpsClientName, lpsClientName))
		{
			return TRUE;
		}
	}

	return FALSE;
}

VOID SendExitToAllParticipants(chatRoom_t* chatRoomToClose)
{
	chat_message_t SendingExitMessage;

	CreateChatMessage(OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT, 0, NULL, &SendingExitMessage);

	for (DWORD dwClientParticipant = 0; dwClientParticipant < chatRoomToClose->dwPartyCounter; dwClientParticipant++)
	{
		if (strcmp(chatRoomToClose->lpsAdminClientName, chatRoomToClose->chatParticipants[dwClientParticipant]->lpsClientName) != 0)
		{
			SendChatMessage(chatRoomToClose->chatParticipants[dwClientParticipant]->clientSocket, chatRoomToClose->chatParticipants[dwClientParticipant]->hCommsKey, SendingExitMessage);
		}
	}
}

VOID DeleteClientFromChatRoom(LPSTR lpsClientName, LPSTR lpsChatRoomName)
{
	chatRoom_t* chatRoomToCheck = GetChatRoomByName(lpsChatRoomName);
	DWORD dwDeleteClient = -1;

	if (!strcmp(chatRoomToCheck->lpsAdminClientName, lpsClientName))
	{
		SendExitToAllParticipants(chatRoomToCheck);

	}

	for (DWORD dwClientInList = 0; dwClientInList < chatRoomToCheck->dwPartyCounter; dwClientInList++)
	{
		if (!strcmp(chatRoomToCheck->chatParticipants[dwClientInList]->lpsClientName, lpsClientName))
		{

			dwDeleteClient = dwClientInList;
			break;
		}

	}

	if (dwDeleteClient == -1)
	{
		printf_s("No such client found\n");
		return;
	}

	chatRoomToCheck->dwPartyCounter--;

	for (DWORD dwClientInList = 0; dwClientInList < chatRoomToCheck->dwPartyCounter; dwClientInList++)
	{
		if (dwClientInList >= dwDeleteClient)
		{
			chatRoomToCheck->chatParticipants[dwClientInList] = chatRoomToCheck->chatParticipants[dwClientInList + 1];
		}
	}

	if (chatRoomToCheck->chatParticipants[chatRoomToCheck->dwPartyCounter])
		HeapFree(GetProcessHeap(), 0, chatRoomToCheck->chatParticipants[dwDeleteClient]);
}

BOOL CheckPrivateChatExistence(LPSTR lpsFirstName, LPSTR lpsSecondName)
{
	chatRoomList_t* chatRoomIter = chatRoomListHead;
	LPSTR lpsChatRoomName;
	LPSTR lpsAlterChatRoomName;
	DWORD dwChatRoomNameSize = (DWORD)strlen(lpsFirstName) + (DWORD)strlen(lpsSecondName) + 2;

	lpsChatRoomName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwChatRoomNameSize);
	if (lpsChatRoomName == NULL)
	{
		printf_s("Problem with HeapAlloc, CheckPrivateChatExistence\n");
		return FALSE;
	}

	snprintf(lpsChatRoomName, dwChatRoomNameSize, "%s-%s", lpsFirstName, lpsSecondName);

	lpsAlterChatRoomName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwChatRoomNameSize);
	if (lpsAlterChatRoomName == NULL)
	{
		printf_s("Problem with HeapAlloc, CheckPrivateChatExistence\n");
		return FALSE;
	}

	snprintf(lpsAlterChatRoomName, dwChatRoomNameSize, "%s-%s", lpsSecondName, lpsFirstName);

	while (chatRoomIter != NULL)
		if (strcmp(chatRoomIter->chatRoom.lpsChatRoomName, lpsChatRoomName) == 0 ||
			strcmp(chatRoomIter->chatRoom.lpsChatRoomName, lpsAlterChatRoomName) == 0)
			break;
		else
			chatRoomIter = chatRoomIter->nextRoom;

	if (chatRoomIter == NULL)
	{
		if (lpsChatRoomName != NULL)
			HeapFree(GetProcessHeap(), 0, lpsChatRoomName);

		if (lpsAlterChatRoomName != NULL)
			HeapFree(GetProcessHeap(), 0, lpsAlterChatRoomName);

		return FALSE;
	}

	if (lpsChatRoomName != NULL)
		HeapFree(GetProcessHeap(), 0, lpsChatRoomName);

	if (lpsAlterChatRoomName != NULL)
		HeapFree(GetProcessHeap(), 0, lpsAlterChatRoomName);

	return TRUE;

}

VOID NewPrivateChatHandle(LPSTR lpsClientName, chat_message_t receivedMessage)
{
	DWORD dwBadClientNameMessageSize = 22;
	LPSTR lpsBadClientNameMessage = "No such client found\n";
	chat_message_t sendingMessage;
	client_t* currentClient = GetClientByName(lpsClientName);
	   
	if (!strcmp(receivedMessage.Data, lpsClientName) || !IsClientExist(receivedMessage.Data) || CheckPrivateChatExistence(lpsClientName, receivedMessage.Data))
	{
		if (CreateChatMessage(OP_FAILED_REPLY_PRIVATE_CHAT, dwBadClientNameMessageSize, lpsBadClientNameMessage, &sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage\n");
			return;
		}

		if (SendChatMessage(currentClient->clientSocket, currentClient->hCommsKey, sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage\n");
			ResetChatMessage(&sendingMessage);

			return;
		}
	}
	else
	{
		StartNewPrivateChat(currentClient->lpsClientName, receivedMessage.Data);
	}
	
	//CHECK here!!!
	//ResetChatMessage(&sendingMessage);
}

DWORD IndexUntilDelim(CHAR cDelim, LPSTR lpsStringToSearch, DWORD dwStringSize)
{
	for (DWORD dwLocationInString = 0; dwLocationInString < dwStringSize; dwLocationInString++)
	{
		if (lpsStringToSearch[dwLocationInString] == cDelim)
			return dwLocationInString;
	}

	return -1;
}

VOID OutcomingChatMessageHandle(chat_message_t receivingMessage, DWORD dwOpCode, LPSTR lpsReceivingClient)
{
	DWORD			dwDataSize = GetDataSizeFromMessage(receivingMessage);
	DWORD			dwChatNameSize = IndexUntilDelim(':', receivingMessage.Data, dwDataSize);
	LPSTR			lpsChatName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwChatNameSize);
	CHAR			cSecondName[BUFFER_SIZE] = "";
	CHAR			cFirstName[BUFFER_SIZE] = "";
	CHAR*			cToken;
	CHAR*			cNextToken = NULL;
	chatRoom_t*		chatRoomToSend;
	chat_message_t	sendingMessage;

	if (lpsChatName == NULL)
	{
		printf_s("Problem with HeapAlloc, OutcomingChatMessageHandle\n");
		return;
	}

	CopyDataString(&lpsChatName, dwChatNameSize, receivingMessage.Data);

	chatRoomToSend = GetChatRoomByName(lpsChatName);
	if (chatRoomToSend == NULL)
	{
		if (IndexUntilDelim('-', receivingMessage.Data, dwDataSize) > dwChatNameSize)
		{
			printf_s("Problem with GetChatRoomByName, OutcomingChatMessageHandle\n");
			return;
		}

		cToken = strtok_s(lpsChatName, "-", &cNextToken);
		strcat_s(cFirstName, BUFFER_SIZE, cToken);
		strcat_s(cSecondName, BUFFER_SIZE, cNextToken);
		memset(lpsChatName, 0, dwChatNameSize);
		dwChatNameSize = (DWORD)strlen(cFirstName) + (DWORD)strlen(cSecondName) + 2;

		snprintf(lpsChatName, dwChatNameSize, "%s-%s", cSecondName, cFirstName);
		chatRoomToSend = GetChatRoomByName(lpsChatName);
	}

	if (chatRoomToSend == NULL)
	{
		printf_s("Problem with GetChatRoomByName, OutcomingChatMessageHandle\n");
		if (lpsChatName != NULL)
			HeapFree(GetProcessHeap(), 0, lpsChatName);

		return;
	}

	if (CreateChatMessage(dwOpCode, dwDataSize, receivingMessage.Data, &sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage\n");
		if (lpsChatName != NULL)
			HeapFree(GetProcessHeap(), 0, lpsChatName);

		return;
	}

	for (DWORD dwChatRoomParticipant = 0; dwChatRoomParticipant < chatRoomToSend->dwPartyCounter; dwChatRoomParticipant++)
	{
		if (strcmp(chatRoomToSend->chatParticipants[dwChatRoomParticipant]->lpsClientName, lpsReceivingClient) != 0)
		{
			if (SendChatMessage(chatRoomToSend->chatParticipants[dwChatRoomParticipant]->clientSocket,
				chatRoomToSend->chatParticipants[dwChatRoomParticipant]->hCommsKey,
				sendingMessage) != 0)
			{
				printf_s("Problem with SendChatMessage\n");
				ResetChatMessage(&sendingMessage);

				if (lpsChatName != NULL)
					HeapFree(GetProcessHeap(), 0, lpsChatName);

				return;
			}
		}
	}

	ResetChatMessage(&sendingMessage);

	if (receivingMessage.Header[0] == OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT)
	{
		if (DeleteChatRoomFromList(lpsChatName) != 0)
		{
			printf_s("Problem with DestroyChatRoom, OutcomingChatMessageHandle\n");
			if (lpsChatName != NULL)
				HeapFree(GetProcessHeap(), 0, lpsChatName);

			return;
		}
	}

	if (lpsChatName != NULL)
		HeapFree(GetProcessHeap(), 0, lpsChatName);
}

DWORD CountAllChatRoomNameSizes()
{
	DWORD dwSizeOfAllNames = 0;
	chatRoomList_t* chatRoomIter = chatRoomListHead;

	while (chatRoomIter != NULL)
	{
		if (IndexUntilDelim('-', chatRoomIter->chatRoom.lpsChatRoomName, (DWORD) strlen(chatRoomIter->chatRoom.lpsChatRoomName)) == -1)
			dwSizeOfAllNames += (DWORD)strlen(chatRoomIter->chatRoom.lpsChatRoomName);

		chatRoomIter = chatRoomIter->nextRoom;
	}

	return dwSizeOfAllNames;
}

DWORD AllChatRoomNamesString(LPSTR* lpsChatRoomNamesString)
{
	DWORD dwSizeOfNamesString = CountAllChatRoomNameSizes();
	DWORD dwIterNumber = 0;
	CHAR sTempBuffer[BUFFER_SIZE];
	chatRoomList_t* chatRoomIter = chatRoomListHead;

	if (dwSizeOfNamesString != 0)
		dwSizeOfNamesString += (dwChatRoomsCounter  * 4);
	else
		return 0;

	*lpsChatRoomNamesString = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeOfNamesString);
	if (*lpsChatRoomNamesString == NULL) return -1;

	while (chatRoomIter != NULL)
	{
		if (IndexUntilDelim('-', chatRoomIter->chatRoom.lpsChatRoomName, (DWORD)strlen(chatRoomIter->chatRoom.lpsChatRoomName)) == -1)
		{
			snprintf(sTempBuffer, BUFFER_SIZE, "%d.\0", dwIterNumber + 1); // for nice printing with ID
			strcat_s(*lpsChatRoomNamesString, dwSizeOfNamesString, sTempBuffer);
			strcat_s(*lpsChatRoomNamesString, dwSizeOfNamesString, chatRoomIter->chatRoom.lpsChatRoomName);
			strcat_s(*lpsChatRoomNamesString, dwSizeOfNamesString, "\n\0");
			dwIterNumber++;
		}

		chatRoomIter = chatRoomIter->nextRoom;
	}

	return dwSizeOfNamesString;
}

VOID SendChatRoomListHandle(LPSTR lpsCurrentClientName)
{
	client_t* currentClient = GetClientByName(lpsCurrentClientName);
	LPSTR lpsChatRoomNames;
	DWORD dwChatRoomNamesSize = 0;
	chat_message_t sendMessage;

	if ((dwChatRoomNamesSize = AllChatRoomNamesString(&lpsChatRoomNames)) < 0)
	{
		printf_s("Problem with AllClientsNamesString, SendClientList\n");
		return;
	}
	else if (dwChatRoomNamesSize == 0)
	{
		dwChatRoomNamesSize = 22;
		lpsChatRoomNames = (CHAR*)HeapAlloc(GetProcessHeap(), 0, dwChatRoomNamesSize * sizeof(CHAR));
		CopyDataString(&lpsChatRoomNames, dwChatRoomNamesSize, "No chat rooms found.\n");
	}

	if (CreateChatMessage(OP_REPLY_CHAT_ROOMS_LIST, dwChatRoomNamesSize, lpsChatRoomNames, &sendMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, SendClientList\n");
		if (lpsChatRoomNames)
			HeapFree(GetProcessHeap(), 0, lpsChatRoomNames);

		return;
	}

	if (SendChatMessage(currentClient->clientSocket, currentClient->hCommsKey, sendMessage) != 0)
	{
		printf_s("Problem with SendChatMessage\n");
		if (lpsChatRoomNames)
			HeapFree(GetProcessHeap(), 0, lpsChatRoomNames);

		ResetChatMessage(&sendMessage);
		return;
	}

	if (lpsChatRoomNames)
		HeapFree(GetProcessHeap(), 0, lpsChatRoomNames);

	ResetChatMessage(&sendMessage);
}

VOID StartNewPublicChat(LPSTR lpsClientName, LPSTR lpsChatRoomName)
{
	chat_message_t sendingMessage;
	LPSTR lpsNewChatMessage;
	DWORD dwChatRoomNameSize = 0;
	DWORD dwNewChatMessageSize = 25;
	DWORD dwChatRoomID;
	client_t* clientStarting = GetClientByName(lpsClientName);

	dwNewChatMessageSize = (DWORD)strlen(lpsChatRoomName) + 1;
	lpsNewChatMessage = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwNewChatMessageSize);
	if (lpsNewChatMessage == NULL)
	{
		printf_s("Problem with HeapAlloc, StartNewPrivateChat\n");
		return;
	}

	CopyDataString(&lpsNewChatMessage, dwNewChatMessageSize, lpsChatRoomName);

	if (CreateChatMessage(OP_SUCCESS_REPLY_PUBLIC_CHAT, dwNewChatMessageSize, lpsNewChatMessage, &sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, StartNewPrivateChat\n");
		return;
	}

	if (SendChatMessage(clientStarting->clientSocket, clientStarting->hCommsKey, sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, StartNewPrivateChat\n");
		ResetChatMessage(&sendingMessage);
		return;
	}

	if (lpsNewChatMessage != NULL)
		HeapFree(GetProcessHeap(), 0, lpsNewChatMessage);

	ResetChatMessage(&sendingMessage);

	dwChatRoomNameSize = (DWORD)strlen(lpsChatRoomName) + 1;
	dwChatRoomID = CreateNewChatRoom(lpsClientName, lpsChatRoomName, dwChatRoomNameSize);
	AddClientToChatRoom(lpsClientName, dwChatRoomID);
}

VOID NewPublicChatHandle(LPSTR lpsRequestingClient, chat_message_t receivedMessage)
{
	//TODO!!!!!!!!!!
	DWORD dwBadChatNameMessageSize = 47;
	LPSTR lpsBadChatNameMessage = "Chat room already exist! try a different name\n";
	chat_message_t sendingMessage;
	client_t* currentClient = GetClientByName(lpsRequestingClient);

	if (IsChatRoomExist(receivedMessage.Data))
	{
		if (CreateChatMessage(OP_FAILED_REPLY_PUBLIC_CHAT, dwBadChatNameMessageSize, lpsBadChatNameMessage, &sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage\n");
			return;
		}

		if (SendChatMessage(currentClient->clientSocket, currentClient->hCommsKey, sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage\n");
			ResetChatMessage(&sendingMessage);
			return;
		}
	}
	else
		StartNewPublicChat(currentClient->lpsClientName, receivedMessage.Data);
}

BOOL IsClientInPartyList(client_t** chatParticipants, DWORD dwChatPartySize, LPSTR lpsClientName)
{
	for (DWORD dwChatParticipant = 0; dwChatParticipant < dwChatPartySize; dwChatParticipant++)
	{
		if (!strcmp(chatParticipants[dwChatParticipant]->lpsClientName, lpsClientName))
		{
			return TRUE;
		}
	}

	return FALSE;
}

DWORD JoinChatRoom(LPSTR lpsRequestingClient, LPSTR lpsChatRoomName)
{
	chatRoom_t* chatRoomToAdd = GetChatRoomByName(lpsChatRoomName);
	client_t * clientAsking = GetClientByName(lpsRequestingClient);
	DWORD dwNewChatMessageSize = (DWORD) strlen(lpsChatRoomName);
	chat_message_t sendingMessage;

	if (IsClientInPartyList(chatRoomToAdd->chatParticipants, chatRoomToAdd->dwPartyCounter, lpsChatRoomName))
	{
		return -1;
	}

	if (AddClientToChatRoom(lpsRequestingClient, chatRoomToAdd->dwChatRoomID) == -1)
	{
		printf_s("Failed to add client to chat room\n");
		return -1;
	}

	if (CreateChatMessage(OP_SUCCESS_REPLY_PUBLIC_CHAT, dwNewChatMessageSize + 1, lpsChatRoomName, &sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, StartNewPrivateChat\n");
		return -1;
	}

	if (SendChatMessage(clientAsking->clientSocket, clientAsking->hCommsKey, sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, StartNewPrivateChat\n");
		ResetChatMessage(&sendingMessage);
		return -1;
	}
	
	ResetChatMessage(&sendingMessage);

	return 0;
}

VOID JoinPublicChatHandle(LPSTR lpsRequestingClient, chat_message_t receivedMessage)
{
	DWORD dwBadChatNameMessageSize = 0;
	LPSTR lpsBadChatNameMessage = "";
	chat_message_t sendingMessage;
	client_t* currentClient = GetClientByName(lpsRequestingClient);
	BOOL bFailed = FALSE;

	if (!IsChatRoomExist(receivedMessage.Data))
	{
		bFailed = TRUE;
		lpsBadChatNameMessage = "Chat room not exist! try a different name\n";
		dwBadChatNameMessageSize = 43;
	}
	else
	{
		if (JoinChatRoom(currentClient->lpsClientName, receivedMessage.Data) == -1)
		{
			bFailed = TRUE;
			lpsBadChatNameMessage = "You are in this group! try a different name\n";
			dwBadChatNameMessageSize = 45;
		}
	}

	if (bFailed)
	{
		if (CreateChatMessage(OP_FAILED_REPLY_PUBLIC_CHAT, dwBadChatNameMessageSize, lpsBadChatNameMessage, &sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage\n");
			return;
		}

		if (SendChatMessage(currentClient->clientSocket, currentClient->hCommsKey, sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage\n");
			ResetChatMessage(&sendingMessage);
			return;
		}

		ResetChatMessage(&sendingMessage);
	}
}

VOID LogoutHandle(LPSTR lpsClientName)
{
	//TODO!!!
}

DWORD CheckNewClientName(SOCKET sokNewClientSocket, chat_message_t* receivedMessage)
{
	LPSTR lpsFailedLogin = "Name already taken. Try again\n";
	DWORD dwFailedLoginSize = 31;
	chat_message_t sendMessage;

	if (ReceiveChatMessage(sokNewClientSocket, NULL, receivedMessage) != 0)
	{
		printf_s("Receive failed!, ClientLogin\n");
		return -1;
	}

	if (IsClientExist(receivedMessage->Data))
	{
		if (CreateChatMessage(OP_LOGIN_FAILED, dwFailedLoginSize, lpsFailedLogin, &sendMessage) != 0)
		{
			printf_s("Problem with CreateChatMessage, ClientLogin\n");
			return -1;
		}

		if (SendChatMessage(sokNewClientSocket, NULL, sendMessage) != 0)
		{
			printf_s("Problem with SendChatMessage, ClientLogin\n");
			ResetChatMessage(&sendMessage);
			return -1;
		}

		return -1;
	}

	return 0;
}

VOID MegaphoneHandle(chat_message_t receivingMessage, LPSTR lpsClientName)
{
	chatRoomList_t* chatRoomIter = chatRoomListHead;
	chat_message_t sendingMessage;
	DWORD dwDataSize = GetDataSizeFromMessage(receivingMessage);
	DWORD dwDataToSendSize = 0;
	LPSTR lpsDataToSend = NULL;
	LPSTR lpsAdminPrefix = "Admin@";
	DWORD dwAdminPrefix = 6;

	while (chatRoomIter != NULL)
	{
		dwDataToSendSize = dwAdminPrefix + (DWORD)strlen(lpsClientName) + (DWORD)strlen(chatRoomIter->chatRoom.lpsChatRoomName) + dwDataSize + 4;
		lpsDataToSend = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwDataToSendSize);
		if (lpsDataToSend == NULL)
		{
			printf_s("Problem with HeapAlloc, MegaphoneHandle\n");
			return;
		}

		strcat_s(lpsDataToSend, dwDataToSendSize, chatRoomIter->chatRoom.lpsChatRoomName);
		strcat_s(lpsDataToSend, dwDataToSendSize, ":");
		strcat_s(lpsDataToSend, dwDataToSendSize, lpsAdminPrefix);
		strcat_s(lpsDataToSend, dwDataToSendSize, lpsClientName);
		strcat_s(lpsDataToSend, dwDataToSendSize, ":");
		strcat_s(lpsDataToSend, dwDataToSendSize, receivingMessage.Data);
		strcat_s(lpsDataToSend, dwDataToSendSize, "\0");

		if (CreateChatMessage(OP_INCOMING_CHAT_MESSAGE, dwDataToSendSize, lpsDataToSend, &sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage\n");
			return;
		}

		for (DWORD dwChatRoomParticipant = 0; dwChatRoomParticipant < chatRoomIter->chatRoom.dwPartyCounter; dwChatRoomParticipant++)
		{
			if (SendChatMessage(chatRoomIter->chatRoom.chatParticipants[dwChatRoomParticipant]->clientSocket,
				chatRoomIter->chatRoom.chatParticipants[dwChatRoomParticipant]->hCommsKey,
				sendingMessage) != 0)
			{
				printf_s("Problem with SendChatMessage\n");
				ResetChatMessage(&sendingMessage);
				return;
			}
		}

		ResetChatMessage(&sendingMessage);

		chatRoomIter = chatRoomIter->nextRoom;
	}
}

VOID AdminDeleteHandle(chat_message_t receivedMessage, LPSTR lpsClientName)
{
	chatRoomList_t* chatRoomToDelete;
	chat_message_t sendingMessage;
	DWORD dwDataSize = GetDataSizeFromMessage(receivedMessage);
	DWORD dwDataToSendSize = 0;
	LPSTR lpsDataToSend = NULL;
	LPSTR lpsAdminPrefix = "Admin@";
	DWORD dwAdminPrefix = 6;
	LPSTR lpsAlterChatRoomName = NULL;
	DWORD dwCheckDelim = IndexUntilDelim('-', receivedMessage.Data, dwDataSize);
	CHAR* caFirstName = NULL;
	CHAR* caSecondName = NULL;

	if (dwCheckDelim != -1)
	{
		chatRoomToDelete = GetChatRoomByName(receivedMessage.Data);
		if (chatRoomToDelete == NULL)
		{
			lpsAlterChatRoomName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * (dwDataSize + 1));
			if (lpsAlterChatRoomName == NULL)
			{
				printf_s("Problem with HeapAlloc, AdminDeleteHandle\n");
				return;
			}

			caFirstName = strtok_s(receivedMessage.Data, "-", &caSecondName);
			snprintf(lpsAlterChatRoomName, dwDataSize + 1, "%s-%s", caSecondName, caFirstName);

			chatRoomToDelete = GetChatRoomByName(receivedMessage.Data);
		}
	}
	else
		chatRoomToDelete = GetChatRoomByName(receivedMessage.Data);

	if (chatRoomToDelete == NULL)
	{
		return;
	}

	dwDataToSendSize = dwAdminPrefix + (DWORD)strlen(lpsClientName) + (DWORD)strlen(chatRoomToDelete->chatRoom.lpsChatRoomName) + 8;
	lpsDataToSend = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CHAR) * dwDataToSendSize);
	if (lpsDataToSend == NULL)
	{
		printf_s("Problem with HeapAlloc, AdminDeleteHandle\n");
		return;
	}

	strcat_s(lpsDataToSend, dwDataToSendSize, chatRoomToDelete->chatRoom.lpsChatRoomName);
	strcat_s(lpsDataToSend, dwDataToSendSize, ":");
	strcat_s(lpsDataToSend, dwDataToSendSize, lpsAdminPrefix);
	strcat_s(lpsDataToSend, dwDataToSendSize, lpsClientName);
	strcat_s(lpsDataToSend, dwDataToSendSize, ":exit");

	if (CreateChatMessage(OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT, dwDataToSendSize, lpsDataToSend, &sendingMessage) != 0)
	{
		printf_s("Problem with SendChatMessage, AdminDeleteHandle\n");
		return;
	}

	for (DWORD dwChatRoomParticipant = 0; dwChatRoomParticipant < chatRoomToDelete->chatRoom.dwPartyCounter; dwChatRoomParticipant++)
	{
		if (SendChatMessage(chatRoomToDelete->chatRoom.chatParticipants[dwChatRoomParticipant]->clientSocket,
			chatRoomToDelete->chatRoom.chatParticipants[dwChatRoomParticipant]->hCommsKey,
			sendingMessage) != 0)
		{
			printf_s("Problem with SendChatMessage, AdminDeleteHandle\n");
			ResetChatMessage(&sendingMessage);
			return;
		}
	}

	ResetChatMessage(&sendingMessage);
	DeleteChatRoomFromList(chatRoomToDelete->chatRoom.lpsChatRoomName);
}

DWORD WINAPI ClientThreadHandle(LPVOID lpParam)
{
	DWORD dwClientChoice = 0;
	DWORD dwDecryptedMessageSize = 0;
	CHAR* cpEndptr = NULL;
	LPSTR lpsReceiveMessage = NULL;
	PBYTE pbDecryptedMessage = NULL;
	client_t* currentClientPointer = NULL;
	chatRoomList_t* chatRoomIter = chatRoomListHead;
	chat_message_t receivingMessage;

	while (CheckNewClientName((SOCKET)lpParam, &receivingMessage) != 0)
	{
		printf_s("Name taken, trying again\n");
	}

	AddNewClientToList((SOCKET)lpParam, &currentClientPointer);

	if (ClientLogin(currentClientPointer, receivingMessage) != 0)
	{
		printf_s("Problem with ClientLogin\n");
		ExitThread(-1);
	}

	while(ReceiveChatMessage(currentClientPointer->clientSocket, currentClientPointer->hCommsKey, &receivingMessage) == 0)
	{
		switch (receivingMessage.Header[0])
		{
		case OP_REQUEST_CLIENT_LIST:
			SendClientListHandle(currentClientPointer->lpsClientName);
			break;
		
		case OP_REQUEST_PRIVATE_CHAT:
			NewPrivateChatHandle(currentClientPointer->lpsClientName, receivingMessage);
			break;

		case OP_OUTCOMING_CHAT_MESSAGE:
			OutcomingChatMessageHandle(receivingMessage, OP_INCOMING_CHAT_MESSAGE, currentClientPointer->lpsClientName);
			break;

		case OP_INCOMING_CHAT_MESSAGE_EXIT:
			OutcomingChatMessageHandle(receivingMessage, OP_INCOMING_CHAT_MESSAGE_EXIT, currentClientPointer->lpsClientName);
			break;

		case OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT:
			OutcomingChatMessageHandle(receivingMessage, OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT, currentClientPointer->lpsClientName);
			break;

		case OP_REQUEST_CHAT_ROOMS_LIST:
			SendChatRoomListHandle(currentClientPointer->lpsClientName);
			break;

		case OP_REQUEST_PUBLIC_CHAT:
			NewPublicChatHandle(currentClientPointer->lpsClientName, receivingMessage);
			break;

		case OP_REQUEST_JOIN_PUBLIC_CHAT:
			JoinPublicChatHandle(currentClientPointer->lpsClientName, receivingMessage);
			break;

		case OP_MEGAPHONE:
			MegaphoneHandle(receivingMessage, currentClientPointer->lpsClientName);
			break;

		case OP_ADMIN_DELETE_CHAT:
			AdminDeleteHandle(receivingMessage, currentClientPointer->lpsClientName);
			break;
		}

		ResetChatMessage(&receivingMessage);
	}

	while (chatRoomIter != NULL)
	{
		if (IsClientInChatRoom(currentClientPointer->lpsClientName, chatRoomIter->chatRoom.lpsChatRoomName))
		{
			DeleteClientFromChatRoom(currentClientPointer->lpsClientName, chatRoomIter->chatRoom.lpsChatRoomName);
		}

		chatRoomIter = chatRoomIter->nextRoom;
	}

	DeleteClientFromList(currentClientPointer->lpsClientName);

	ExitThread(0);
}

DWORD FindOpenThread(HANDLE * hThreadsList)
{
	for (DWORD dwThreadNumber = 0; dwThreadNumber < MAX_CLIENTS; dwThreadNumber++)
	{
		if (hThreadsList[dwThreadNumber] == NULL)
			return dwThreadNumber;
	}
	return -1;
}

DWORD AcceptNewClient(SOCKET clientSocket)
{
	DWORD dwOpenThreadNumber = FindOpenThread(haThreadArray);

	dwClientCounter++;

	if (dwOpenThreadNumber == -1)
	{
		printf_s("Cannot accept new client\n");
		return -1;
	}
	else
		haThreadArray[dwOpenThreadNumber] = CreateThread(NULL, 0, ClientThreadHandle, (LPVOID)clientSocket, 0, NULL);

	return 0;
}

DWORD AllClientsNamesString(LPSTR lpsAskingClient, LPSTR *lpsClientsNames)
{
	DWORD dwSizeOfNamesString = CountAllNamesSizes(lpsAskingClient);
	DWORD dwIterNumber = 0;
	CHAR sTempBuffer[BUFFER_SIZE];
	clientList_t* clientIter = clientListHead;

	if (dwSizeOfNamesString != 0)
		dwSizeOfNamesString += ((dwClientCounter-1) * 4);
	else
		return 0;

	*lpsClientsNames = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeOfNamesString);
	if (*lpsClientsNames == NULL) return -1;
	
	while (clientIter != NULL)
	{
		if (strcmp(clientIter->ClientData.lpsClientName, lpsAskingClient) != 0)
		{
			snprintf(sTempBuffer, BUFFER_SIZE, "%d.\0", dwIterNumber + 1); // for nice printing with ID
			strcat_s(*lpsClientsNames, dwSizeOfNamesString, sTempBuffer);
			strcat_s(*lpsClientsNames, dwSizeOfNamesString, clientIter->ClientData.lpsClientName);
			strcat_s(*lpsClientsNames, dwSizeOfNamesString, "\n\0");
			dwIterNumber++;
		}

		clientIter = clientIter->nextClient;
	}

	return dwSizeOfNamesString;
}

DWORD CountAllNamesSizes(LPSTR lpsAskingClient)
{
	DWORD dwSizeOfAllNames = 0;
	clientList_t* clientIter = clientListHead;

	while (clientIter != NULL)
	{
		if (strcmp(clientIter->ClientData.lpsClientName, lpsAskingClient) != 0)
			dwSizeOfAllNames += (DWORD)strlen(clientIter->ClientData.lpsClientName);

		clientIter = clientIter->nextClient;
	}

	return dwSizeOfAllNames;
}

int main()
{
	HANDLE* hThreadArray = (HANDLE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HANDLE));
    WSADATA wsa;
	SOCKET acceptingSocket;
	DWORD dwSizeSockaddr;
	client_t temp_client;
	struct sockaddr_in temp_addr;

	if (InitWinsock(&wsa))
		return 1;

	if (CreateAcceptingSocket(&acceptingSocket))
		return 1;
	
	listen(acceptingSocket , 3);
	
	printf_s("Waiting for incoming connections...\n");
	
	dwSizeSockaddr = sizeof(struct sockaddr_in);
	while((temp_client.clientSocket = accept(acceptingSocket , (struct sockaddr *)& temp_addr, &dwSizeSockaddr)) != INVALID_SOCKET)
	{
		printf_s("Connection accepted\n");
		AcceptNewClient(temp_client.clientSocket);
	}
    
	if (temp_client.clientSocket == INVALID_SOCKET)
	{
		printf("accept failed with error code : %d" , WSAGetLastError());
	}

	closesocket(acceptingSocket);
	WSACleanup();

	return 0;

}