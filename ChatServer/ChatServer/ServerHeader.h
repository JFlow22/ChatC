#ifndef SERVER_H_
#define SERVER_H_

#include <winsock2.h>
#include <ws2tcpip.h>

#define MAX_CLIENTS         50
#define BUFFER_SIZE	        1024
#define SERVER_IP_ADDR      "10.0.0.122"
#define ADMIN_COUNT         3

typedef struct client{
    SOCKET              clientSocket;
    LPSTR               lpsClientName;
    BCRYPT_KEY_HANDLE   hCommsKey;
    PBYTE               pbKeyObject;
    DWORD               cbKeyObject;
} client_t;

client_t*       clients;
DWORD           dwClientCounter = 0;
DWORD           dwChatRoomsCounter = 0;

HANDLE  haThreadArray[MAX_CLIENTS];

LPSTR lpsaAdmins[ADMIN_COUNT] = { "yarden", "shuli", "train" };



#endif