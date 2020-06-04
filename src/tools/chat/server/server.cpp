#include "msquicpublichelper.h"

#include <mutex>
#include <unordered_map>
#include <string>
#include <cstring>
#include <algorithm>

std::mutex setMutex;
std::unordered_map<HQUIC, std::string> streamMap;

const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };
const uint16_t UdpPort = 4567;
const uint64_t IdleTimeoutMs = 10000;

const QUIC_API_TABLE* MsQuic;

QUIC_SEC_CONFIG* SecurityConfig;

static QUIC_BUFFER* CloneBuffer(const QUIC_BUFFER* buf) {
    auto newBufRaw = malloc(sizeof(QUIC_BUFFER) + buf->Length);
    auto data = (uint8_t*)newBufRaw + sizeof(QUIC_BUFFER);
    std::copy_n(buf->Buffer, (size_t)buf->Length, data);
    auto newBuf = (QUIC_BUFFER*)newBufRaw;
    newBuf->Buffer = data;
    newBuf->Length = buf->Length;
    return newBuf;
}

static void HandleDataReceive(QUIC_STREAM_EVENT& event) {
    //printf("Received %d %d\n", event.RECEIVE.BufferCount, (int)event.RECEIVE.TotalBufferLength);



    std::lock_guard lock{setMutex};

    printf("Length of map %d\n", (int)streamMap.size());

    for (auto&& client : streamMap) {
        for (uint32_t i = 0; i < event.RECEIVE.BufferCount; i++) {
            auto& buf = event.RECEIVE.Buffers[i];
            if (buf.Length == 2 && buf.Buffer[0] == 0 && buf.Buffer[1] == 0) continue;
            // Clone buffer
            auto newBuf = CloneBuffer(&event.RECEIVE.Buffers[i]);
            QUIC_STATUS status = MsQuic->StreamSend(client.first, newBuf, 1, QUIC_SEND_FLAG_NONE, newBuf);
            if (QUIC_FAILED(status)) {
                printf("StreamSend failed, 0x%x!\n", status);
                free(newBuf);
                MsQuic->StreamShutdown(client.first, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            }
        }
    }
}

QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        free(Event->SEND_COMPLETE.ClientContext);
        //printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        HandleDataReceive(*Event);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        printf("[strm][%p] Peer shutdown\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        //SendShutdown(Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        printf("[strm][%p] Peer aborted\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("[strm][%p] All done\n", Stream);
        {
            std::lock_guard lock{setMutex};
            streamMap.erase(Stream);
        }
        MsQuic->StreamClose(Stream);
        
        break;
    default:
        printf("Server received default %d\n", Event->Type);
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] All done\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        {
            std::lock_guard lock{setMutex};
            streamMap[Event->PEER_STREAM_STARTED.Stream] = "Unknown";
        }
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, nullptr);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, nullptr);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

int main(int argc, char* argv[]) {
    // First things first, check token

    QUIC_STATUS status = MsQuicOpen(&MsQuic);
    if (QUIC_FAILED(status)) {
        printf("MsQuicOpen failed, %s\n", QuicStatusToString(status));
        return -1;
    }

    HQUIC Registration;
    HQUIC Session;

    if (QUIC_FAILED(status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, %s\n", QuicStatusToString(status));
        MsQuicClose(MsQuic);
        return -1;
    }

    if (QUIC_FAILED(status = MsQuic->SessionOpen(Registration, &Alpn, 1, nullptr, &Session))) {
        printf("SessionOpen failed, %s\n", QuicStatusToString(status));
        MsQuic->RegistrationClose(Registration);
        MsQuicClose(MsQuic);
    }

    if (QUIC_FAILED(status = MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_IDLE_TIMEOUT,
        sizeof(IdleTimeoutMs), &IdleTimeoutMs))) {
            printf("SetParam failed, %s\n", QuicStatusToString(status));
            MsQuic->SessionClose(Session);
            MsQuic->RegistrationClose(Registration);
            MsQuicClose(MsQuic);
        }

    QUIC_ADDR Address = {};
    Address.si_family = AF_UNSPEC;
    Address.Ipv4.sin_port = htons(UdpPort);

    const uint16_t PeerStreamCount = 1;
    HQUIC Listener = nullptr;

    const char* Cert;
    const char* KeyFile;
    if (TryGetValue(argc, argv, "cert_hash", &Cert)) {
        SecurityConfig = GetSecConfigForThumbprint(MsQuic, Registration, Cert);
        if (SecurityConfig == nullptr) {
            printf("Failed to load certificate from hash!\n");
            goto Exit;
        }
    } else if (TryGetValue(argc, argv, "cert_file", &Cert) &&
        TryGetValue(argc, argv, "key_file", &KeyFile)) {
        SecurityConfig = GetSecConfigForFile(MsQuic, Registration, KeyFile, Cert);
        if (SecurityConfig == nullptr) {
            printf("Failed to load certificate from file!\n");
            goto Exit;
        }
    } else {
        printf("Must specify '-cert_hash' or 'cert_file'!\n");
        goto Exit;
    }

    

    if (QUIC_FAILED(status = MsQuic->SetParam(
            Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT,
            sizeof(PeerStreamCount), &PeerStreamCount))) {
        printf("SetParam(QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT) failed, %s!\n", QuicStatusToString(status));
        goto Exit;
    }

    if (QUIC_FAILED(status = MsQuic->ListenerOpen(Session, ServerListenerCallback, nullptr, &Listener))) {
        printf("ListenerOpen failed, %s!\n", QuicStatusToString(status));
        goto Exit;
    }

    if (QUIC_FAILED(status = MsQuic->ListenerStart(Listener, &Address))) {
        printf("ListenerStart failed, %s!\n", QuicStatusToString(status));
        goto Exit;
    }

    printf("Press Enter to exit.\n\n");
    getchar();


Exit:
    if (Listener != nullptr) {
        MsQuic->ListenerClose(Listener);
    }
    MsQuic->SecConfigDelete(SecurityConfig);

    if (MsQuic != nullptr) {
        if (Session != nullptr) {
            MsQuic->SessionClose(Session); // Waits on all connections to be cleaned up.
        }
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }
}