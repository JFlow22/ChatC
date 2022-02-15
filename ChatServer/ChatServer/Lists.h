#ifndef LISTS_H_
#define LISTS_H_

#include <stdio.h>
#include "ServerHeader.h"

typedef struct clientList {
	client_t ClientData;
	struct clientList* nextClient;
}clientList_t;

typedef struct chatRoom {
	DWORD       dwChatRoomID;
	LPSTR		lpsChatRoomName;
	DWORD       dwPartyCounter;
	LPSTR       lpsAdminClientName;
	struct client** chatParticipants;
}chatRoom_t;

typedef struct chatRoomList{
	chatRoom_t chatRoom;
	struct chatRoomList* nextRoom;
} chatRoomList_t;

chatRoomList_t* chatRoomListHead = NULL;
clientList_t* clientListHead = NULL;

VOID NewChatRoom(chatRoom_t* chatRoomToAdd, LPSTR lpsClientStarting, DWORD dwPrevRoomID, LPSTR lpsChatRoomName, DWORD dwChatRoomNameSize);
DWORD AddNewChatRoom(LPSTR lpsClientStarting, LPSTR lpsChatRoomName, DWORD dwChatRoomNameSize);
client_t* GetClientByName(LPSTR lpsClientName);
DWORD AddClientToChatRoom(LPSTR lpsClientName, DWORD dwChatRoomID);
VOID AddNewClientToList(SOCKET sokClientSocket, client_t** clientAdded);
VOID ClientListInit();
VOID ChatRoomListInit();


VOID NewChatRoom(chatRoom_t* chatRoomToAdd, LPSTR lpsClientStarting, DWORD dwPrevRoomID, LPSTR lpsChatRoomName, DWORD dwChatRoomNameSize)
{
	client_t* clientStating = GetClientByName(lpsClientStarting);

	dwChatRoomsCounter++;
	chatRoomToAdd->dwPartyCounter = 0;
	chatRoomToAdd->dwChatRoomID = dwPrevRoomID + 1;
	chatRoomToAdd->lpsAdminClientName = clientStating->lpsClientName;
	if (dwChatRoomNameSize != 0)
	{
		chatRoomToAdd->lpsChatRoomName = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwChatRoomNameSize * sizeof(CHAR));
		if (chatRoomToAdd->lpsChatRoomName == NULL)
		{
			printf_s("Problem with HeapAlloc, CreateNewChatRoom\n");
			return;
		}

		CopyDataString(&(chatRoomToAdd->lpsChatRoomName), dwChatRoomNameSize, lpsChatRoomName);
	}
	else
		chatRoomToAdd->lpsChatRoomName = NULL;

	chatRoomToAdd->chatParticipants = (client_t**)HeapAlloc(GetProcessHeap(), 0, sizeof(client_t*));
	if (chatRoomToAdd->chatParticipants == NULL)
	{
		printf_s("Problem with HeapAlloc, NewChatRoom\n");
		if (chatRoomToAdd->lpsChatRoomName != NULL)
			HeapFree(GetProcessHeap(), 0, chatRoomToAdd->lpsChatRoomName);

		return;
	}
}

DWORD AddNewChatRoom(LPSTR lpsClientStarting, LPSTR lpsChatRoomName, DWORD dwChatRoomNameSize)
{
	DWORD dwPrevRoomID = 0;
	chatRoomList_t* chatRoomIter = chatRoomListHead;

	if (chatRoomListHead == NULL)
	{
		ChatRoomListInit();
		if (chatRoomListHead == NULL) return -1;
		NewChatRoom(&(chatRoomListHead->chatRoom), lpsClientStarting, dwPrevRoomID, lpsChatRoomName, dwChatRoomNameSize);
		return 1;
	}

	while (chatRoomIter->nextRoom != NULL)
	{
		chatRoomIter = chatRoomIter->nextRoom;
	}

	dwPrevRoomID = chatRoomIter->chatRoom.dwChatRoomID;
	chatRoomIter->nextRoom = (chatRoomList_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(chatRoomList_t));
	if (chatRoomIter->nextRoom == NULL)
	{
		printf_s("Problem with HeapAlloc, AddNewChatRoom\n");
		return -1;
	}

	NewChatRoom(&(chatRoomIter->nextRoom->chatRoom), lpsClientStarting, dwPrevRoomID, lpsChatRoomName, dwChatRoomNameSize);
	chatRoomIter->nextRoom->nextRoom = NULL;

	return dwPrevRoomID + 1;
}

client_t* GetClientByName(LPSTR lpsClientName)
{
	clientList_t *clientIter = clientListHead;

	while (clientIter != NULL)
		if (strcmp(clientIter->ClientData.lpsClientName, lpsClientName) == 0)
			break;
		else
			clientIter = clientIter->nextClient;

	if (clientIter == NULL) return NULL;

	return &(clientIter->ClientData);
}

chatRoom_t* GetChatRoomByName(LPSTR lpsChatRoomName)
{
	chatRoomList_t* chatRoomIter = chatRoomListHead;

	while (chatRoomIter != NULL)
		if (strcmp(chatRoomIter->chatRoom.lpsChatRoomName, lpsChatRoomName) == 0)
			break;
		else
			chatRoomIter = chatRoomIter->nextRoom;

	if (chatRoomIter == NULL) return NULL;

	return &(chatRoomIter->chatRoom);
}

DWORD AddClientToChatRoom(LPSTR lpsClientName, DWORD dwChatRoomID)
{
	chatRoomList_t* ChatRoomIter = chatRoomListHead;
	client_t** chatRoomTemp;

	while (ChatRoomIter != NULL)
		if (ChatRoomIter->chatRoom.dwChatRoomID != dwChatRoomID)
			ChatRoomIter = ChatRoomIter->nextRoom;
		else
			break;

	if (ChatRoomIter == NULL)
	{
		printf_s("Problem with AddClientToChatRoom\n");
		return -1;
	}

	ChatRoomIter->chatRoom.dwPartyCounter++;
	chatRoomTemp = (client_t**)HeapReAlloc(GetProcessHeap(), 0, ChatRoomIter->chatRoom.chatParticipants,
		sizeof(client_t*) * ChatRoomIter->chatRoom.dwPartyCounter);

	if (chatRoomTemp == NULL)
	{
		printf_s("Problem with HeapReAlloc, AddClientToChatRoom\n");
		return -1;
	}

	ChatRoomIter->chatRoom.chatParticipants = chatRoomTemp;
	(ChatRoomIter->chatRoom.chatParticipants)[ChatRoomIter->chatRoom.dwPartyCounter - 1] = GetClientByName(lpsClientName);

	return 0;
}

VOID AddNewClientToList(SOCKET sokClientSocket, client_t** clientAdded)
{
	clientList_t* clientIter = clientListHead;

	if (clientListHead == NULL)
	{
		ClientListInit();
		if (clientListHead == NULL) return;
		clientListHead->ClientData.clientSocket = sokClientSocket;
		*clientAdded = &(clientListHead->ClientData);
		return;
	}

	while (clientIter->nextClient != NULL)
		clientIter = clientIter->nextClient;

	clientIter->nextClient = (clientList_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(clientList_t));
	if (clientIter->nextClient == NULL)
	{
		printf_s("Problem with HeapAlloc, AddNewChatRoom\n");
		return;
	}

	clientIter->nextClient->nextClient = NULL;
	clientIter->nextClient->ClientData.clientSocket = sokClientSocket;

	*clientAdded = &(clientIter->nextClient->ClientData);
}

VOID ChatRoomListInit()
{
	chatRoomListHead = (chatRoomList_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(chatRoomList_t));

	if (chatRoomListHead == NULL)
	{
		printf_s("Problem with HeapAlloc, ClientListInit\n");
		return;
	}

	chatRoomListHead->nextRoom = NULL;
}

VOID ClientListInit()
{
	clientListHead = (clientList_t*)HeapAlloc(GetProcessHeap(), 0, sizeof (clientList_t));

	if (clientListHead == NULL)
	{
		printf_s("Problem with HeapAlloc, ClientListInit\n");
		return;
	}

	clientListHead->nextClient = NULL;
}

chatRoom_t* GetChatRoomByID(DWORD dwChatRoomID)
{
	chatRoomList_t* chatRoomIter = chatRoomListHead;

	while (chatRoomIter != NULL)
		if (chatRoomIter->chatRoom.dwChatRoomID == dwChatRoomID)
			break;
		else
			chatRoomIter = chatRoomIter->nextRoom;

	if (chatRoomIter == NULL) return NULL;

	return &(chatRoomIter->chatRoom);
}

#endif // !LISTS_H_
