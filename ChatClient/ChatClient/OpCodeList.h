#ifndef OPCODELIST_H_
#define OPCODELIST_H_

// client requests

#define		OP_LOGIN_REQUEST						10
#define		OP_LOGIN_PUBLIC_KEY						112
#define		OP_LOGIN_CHECK_ADMIN					113
#define		OP_LOGOUT								0
#define		OP_REQUEST_CLIENT_LIST					1
#define		OP_REQUEST_PRIVATE_CHAT					2
#define		OP_REQUEST_CHAT_ROOMS_LIST				3
#define		OP_REQUEST_PUBLIC_CHAT					4
#define		OP_REQUEST_JOIN_PUBLIC_CHAT				5

// admin rights
#define		OP_MEGAPHONE							6
#define		OP_ADMIN_DELETE_CHAT					7

// chat message
#define		OP_OUTCOMING_CHAT_MESSAGE				9

// key exchange
#define		OP_REPLY_ASYMMETRIC_KEY					100
#define		OP_SERVER_REPLY_SYMMETRIC_KEY			101

// Server requests

#define		OP_LOGIN_ASK_KEY						111
#define		OP_LOGIN_AS_ADMIN						114
#define		OP_LOGIN_AS_NORMAL						115
#define		OP_LOGIN_FAILED							11
#define		OP_LOGIN_KEY_REPLY						10
#define		OP_REPLY_CLIENT_LIST					1
#define		OP_SUCCESS_REPLY_PRIVATE_CHAT			21
#define		OP_FAILED_REPLY_PRIVATE_CHAT			22
#define		OP_REPLY_CHAT_ROOMS_LIST				3
#define		OP_SUCCESS_REPLY_PUBLIC_CHAT			41
#define		OP_FAILED_REPLY_PUBLIC_CHAT				42
#define		OP_REPLY_JOIN_PUBLIC_CHAT				5

// chat message
#define		OP_INCOMING_CHAT_MESSAGE				9
#define		OP_INCOMING_CHAT_MESSAGE_EXIT			90
#define		OP_INCOMING_ADMIN_CHAT_MESSAGE_EXIT		99

#endif // !OPCODELIST_H_