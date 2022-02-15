#pragma once
#ifndef CLIENT_H_
#define CLIENT_H_

#include <stdlib.h>
#include <ws2tcpip.h>
#include "TransmissionHeader.h"
#include "Encryption.h"
#include "OpCodeList.h"
#include "CommunicationAPI.h"

#define BUFFER_SIZE 4096
#define CHATS_LIMIT 50
#define SIZE_USERNAME 50
#define PORT_NUM 8888
#define SERVER_IP_ADDR "10.0.0.122"
#define SIZE_INBOUND_PREFIX 12
#define SIZE_OUTBOUND_PREFIX 13
#define PRIVATE_KEY_SIZE 440
#define PUBLIC_KEY_SIZE 130

typedef struct pipeHandleList {
	LPSTR		lpsPipeName;
	HANDLE		lphPipeHandles[2]; // first is INBOUND and second is OUTBOUND
	struct pipeHandleList* nextPipesHandle;
}pipeHandleList_t;

typedef struct threadParams{
	CHAR lpsChatName[BUFFER_SIZE];
	BOOL bIsPrivate;
}threadParams_t;

LPHANDLE GetHandlesByName(LPSTR lpsPipeName);
pipeHandleList_t* GetLastPipeHandles();
DWORD InitWinsock();
DWORD ConnectSocket();
DWORD Login();
DWORD OptionsMenu();
DWORD GetEncryptionKey(LPSTR cpBlob, DWORD dwBlob);
DWORD AcceptUsernameFromClient(LPSTR* lpsChosenClientName);
DWORD WINAPI ReceivingThreadHandle(LPVOID lpParam);
DWORD WINAPI SendingThreadHandle(LPVOID lpParam);
VOID ReleasePipeHandlesList(pipeHandleList_t* handlesIter);
VOID PipeHandlesListInit();
VOID PrintAllUserNames(LPSTR lpsAllUserNames);
VOID ClientListPrintHandle(chat_message_t receivingMessage);
VOID StartNewPrivateChat(chat_message_t receivedMessage);
VOID FailedPrivateChatPrint(chat_message_t receivedMessage);
VOID StartChatRoutine();
BOOL CreateChatProcess(LPSTR lpsProcessTitle, LPSTR lpsChatName, BOOL bIsPrivate);
DWORD IndexUntilDelim(CHAR cDelim, LPSTR lpsStringToSearch, DWORD dwStringSize);

#endif // !CLIENT_H_