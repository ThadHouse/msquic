/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides a very simple MsQuic API sample chat application client library

--*/

#include "client.h"

#include "msquic.h"

#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <string>

inline
_Null_terminated_
const char*
QuicStatusToString(
    _In_ QUIC_STATUS Status
    )
{
    switch (Status) {
    case QUIC_STATUS_SUCCESS:                   return "SUCCESS";
    case QUIC_STATUS_OUT_OF_MEMORY:             return "OUT_OF_MEMORY";
    case QUIC_STATUS_INVALID_PARAMETER:         return "INVALID_PARAMETER";
    case QUIC_STATUS_INVALID_STATE:             return "INVALID_STATE";
    case QUIC_STATUS_NOT_SUPPORTED:             return "NOT_SUPPORTED";
    case QUIC_STATUS_NOT_FOUND:                 return "NOT_FOUND";
    case QUIC_STATUS_BUFFER_TOO_SMALL:          return "BUFFER_TOO_SMALL";
    case QUIC_STATUS_HANDSHAKE_FAILURE:         return "HANDSHAKE_FAILURE";
    case QUIC_STATUS_ABORTED:                   return "ABORTED";
    case QUIC_STATUS_ADDRESS_IN_USE:            return "ADDRESS_IN_USE";
    case QUIC_STATUS_CONNECTION_TIMEOUT:        return "CONNECTION_TIMEOUT";
    case QUIC_STATUS_CONNECTION_IDLE:           return "CONNECTION_IDLE";
    case QUIC_STATUS_UNREACHABLE:               return "UNREACHABLE";
    case QUIC_STATUS_INTERNAL_ERROR:            return "INTERNAL_ERROR";
    case QUIC_STATUS_SERVER_BUSY:               return "SERVER_BUSY";
    case QUIC_STATUS_PROTOCOL_ERROR:            return "PROTOCOL_ERROR";
    case QUIC_STATUS_VER_NEG_ERROR:             return "VER_NEG_ERROR";
    }

    return "UNKNOWN";
}

#pragma warning(disable: 4100)
#pragma warning(disable: 4505)

const QUIC_API_TABLE* MsQuic = nullptr;
std::string Name;
std::string IpAddress;
std::atomic<HQUIC> SendToStream{nullptr}; 

std::mutex waitMutex;
std::condition_variable waitCond;

std::atomic_bool ThreadRunning{false};

std::atomic_bool ConnectionRetry{false};

std::thread* thr;

HQUIC Registration;
HQUIC Session;

QuicChatMessageReceiveFn ReceiveFunction;
void* ReceiveContext;

const uint16_t UdpPort = 4567;

static QUIC_STATUS QUIC_API ClientConnectionCallback(
    HQUIC connection,
    void* context,
    QUIC_CONNECTION_EVENT* event
);

static void ThreadMain() {
    while (ThreadRunning) {
        {
            std::unique_lock lock{waitMutex};
            waitCond.wait_for(lock, std::chrono::seconds(1));
        }
        if (!ThreadRunning) break;
        auto stream = SendToStream.load();
        if (!stream) {
            if (ConnectionRetry) {
                // Retry connection
                printf("trying connection\n");
                HQUIC connection;
                QUIC_STATUS status = MsQuic->ConnectionOpen(Session, ClientConnectionCallback, nullptr, &connection );
                if (QUIC_SUCCEEDED(status)) {
                    status = MsQuic->ConnectionStart(connection, AF_UNSPEC, IpAddress.c_str(), UdpPort);
                    if (QUIC_SUCCEEDED(status)) {
                        printf("Succeeded\n");
                        ConnectionRetry = false;
                    } else {
                        printf("Failed\n");
                        MsQuic->ConnectionClose(connection);
                    }
                }
            }
            continue;
        }
        auto buffer = malloc(sizeof(QUIC_BUFFER) + 2); // hb
        auto strStart = (char*) buffer + sizeof(QUIC_BUFFER);
        strStart[0] = '\0';
        strStart[1] = '\0';
        auto qBuffer = (QUIC_BUFFER*)buffer;
        qBuffer->Buffer = (uint8_t*)strStart;
        qBuffer->Length = 2;

        auto s = MsQuic->StreamSend(stream, qBuffer, 1, QUIC_SEND_FLAG_NONE, qBuffer);

        if (QUIC_FAILED(s)) {
            printf("Stream Send Failed\n");
            free(buffer);
        }

        //free(buffer);

        printf("HB Status %d %s %p\n", s, QuicStatusToString(s), buffer);


        
    }

    printf("Finishing thread\n");
    auto str = SendToStream.load();
    if (str) {
        auto sr = MsQuic->StreamShutdown(str, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        printf("Shutdown result %s\n", QuicStatusToString(sr));
    }
}

static void HandleDataReceive(QUIC_STREAM_EVENT& event) {
    printf("Received %d %d\n", event.RECEIVE.BufferCount, (int)event.RECEIVE.TotalBufferLength);

    if (!ReceiveFunction) return;

    for (uint32_t i = 0; i < event.RECEIVE.BufferCount; i++) {
        auto buf = event.RECEIVE.Buffers + i;
        ReceiveFunction(ReceiveContext, buf->Buffer, buf->Length);
    }
}

static QUIC_STATUS QUIC_API ClientStreamCallback(
    HQUIC stream,
    void* context,
    QUIC_STREAM_EVENT* event
) {
    HQUIC conn;
    switch (event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        printf("Send Complete %p\n", event->SEND_COMPLETE.ClientContext);
        free(event->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        HandleDataReceive(*event);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("Stream Shutdown complete\n");
        SendToStream = nullptr;
        MsQuic->StreamClose(stream);
        conn = (HQUIC)context;
        MsQuic->ConnectionShutdown(conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

static void ClientOpenStream(HQUIC connection) {
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    HQUIC stream = nullptr;

    if (QUIC_FAILED(status = MsQuic->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, connection, &stream))) {
        MsQuic->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return; // TODO figure out what cases could cause this to actually happen
    }

    if (QUIC_FAILED(status = MsQuic->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE))) {
        MsQuic->StreamClose(stream);
        MsQuic->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return;
    }

    // TODO: Send Name

    SendToStream = stream;
}

static QUIC_STATUS QUIC_API ClientConnectionCallback(
    HQUIC connection,
    void* context,
    QUIC_CONNECTION_EVENT* event
) {
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        ClientOpenStream(connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(connection);
        ConnectionRetry = true;
        printf("closed\n");
        break; // TODO Restart the connection on shutdown
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("Shutdown Transport %s\n", QuicStatusToString(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status));
        break;
    default:
        printf("default %d\n", event->Type);
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };



extern "C" {

int CHAT_API QuicChatClientStart(const char* name, const char* ipAddr, QuicChatMessageReceiveFn receiveFn,
        void* context) {
    Name = name;
    IpAddress = ipAddr;
    ReceiveFunction = receiveFn;
    ReceiveContext = context;

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(status = MsQuicOpen(&MsQuic))) {
        return 0;
    }

    if (QUIC_FAILED(status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        MsQuicClose(MsQuic);
        return 0;
    }

    if (QUIC_FAILED(status = MsQuic->SessionOpen(Registration, &Alpn, 1, nullptr, &Session))) {
        MsQuic->RegistrationClose(Registration);
        MsQuicClose(MsQuic);
        return 0;
    }

    ConnectionRetry = true;
    ThreadRunning = true;

    thr = new std::thread(ThreadMain);

    waitCond.notify_all();

    return 1;
}

void CHAT_API QuicChatClientEnd() {
    ConnectionRetry = false;
    ThreadRunning = false;

    waitCond.notify_all();

    if (thr) {
        if (thr->joinable()) thr->join();
    }

    if (MsQuic) {
        if (Session) MsQuic->SessionClose(Session);
        if (Registration) MsQuic->RegistrationClose(Registration);
        MsQuicClose(MsQuic);
    }
    
}

void CHAT_API QuicChatSendMessage (const uint8_t* message, uint32_t len) {
    auto stream = SendToStream.load();

    if (!stream) return;

    auto newBufRaw = malloc(sizeof(QUIC_BUFFER) + len);
    auto data = (uint8_t*)newBufRaw + sizeof(QUIC_BUFFER);
    std::copy_n(message, len, data);
    auto newBuf = (QUIC_BUFFER*)newBufRaw;
    newBuf->Buffer = data;
    newBuf->Length = len;

    QUIC_STATUS status = MsQuic->StreamSend(stream, newBuf, 1, QUIC_SEND_FLAG_NONE, newBuf);
    if (QUIC_FAILED(status)) {
        printf("StreamSend failed, 0x%x!\n", status);
        free(newBuf);
        MsQuic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

}