#ifndef _QUICCLIENT_
#define _QUICCLIENT_

#ifdef _WIN32
#pragma once
#endif

#include <stdint.h>

#ifdef _WIN32
#define CHAT_API __cdecl
#else
#define CHAT_API
#endif


typedef void(CHAT_API * QuicChatMessageReceiveFn)(void* context, const uint8_t* buf, uint32_t len);

#ifdef __cplusplus
extern "C" {
#endif

int CHAT_API QuicChatClientStart(const char* name, const char* ipAddr, QuicChatMessageReceiveFn receiveFn, void* receiveContext);

void CHAT_API QuicChatClientEnd();

void CHAT_API QuicChatSendMessage(const uint8_t* message, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif