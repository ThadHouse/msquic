#include <msquiccpp.h>
#define QUIC_TEST_APIS 1
#include <quic_platform.h>

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
const char* Alpn = "sample";

//
// The UDP port used by the server side of the protocol.
//
const uint16_t UdpPort = 4567;

//
// The default idle timeout period (1 second) used for the protocol.
//
const uint64_t IdleTimeoutMs = 1000;

//
// The length of buffer sent over the streams in the protocol.
//
const uint32_t SendBufferLength = 100;



void ServerSend(const ms::quic::Stream& Stream) {
    //
    // Allocates and builds the buffer to send over the stream.
    //
    auto SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == nullptr) {
        printf("SendBuffer allocation failed!\n");
        Stream.Shutdown(QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return;
    }
    auto SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = SendBufferLength;

    printf("[strm][%p] Sending data...\n", (HQUIC)Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = Stream.Send(SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        Stream.Shutdown(QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

QUIC_STATUS ServerStreamCallback(ms::quic::Stream& Stream, QUIC_STREAM_EVENT* Event) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", (HQUIC)Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        printf("[strm][%p] Data received\n", (HQUIC)Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", (HQUIC)Stream);
        ServerSend(Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", (HQUIC)Stream);
        Stream.Shutdown(QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. Cleanup can now safely occur.
        // The Stream will be closed when all references are released.
        // This event occuring will both release the callback, releasing any captures,
        // and release the streams handle on itself.
        //
        printf("[strm][%p] All done\n", (HQUIC)Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS ServerConnectionCallback(ms::quic::Connection& Connection, QUIC_CONNECTION_EVENT* Event) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", (HQUIC)Connection);
        Connection.SendResumptionTicket(QUIC_SEND_RESUMPTION_FLAG_NONE, nullptr, 0);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        printf("[conn][%p] Shut down by transport, 0x%x\n", (HQUIC)Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", (HQUIC)Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up. Cleanup can now safely occur.
        // The connection will be closed when all references are released.
        // This event occuring will both release the callback, releasing any captures,
        // and release the connection handle on itself.
        //
        printf("[conn][%p] All done\n", (HQUIC)Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
    {
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        auto strm = Connection.GetPeerStream(Event);
        strm.SetStreamFunc(ServerStreamCallback);
        break;
    }
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", (HQUIC)Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

int main() {
    QuicPlatformSystemLoad();
    QuicPlatformInitialize();

    auto SelfCert = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);

    {
        ms::quic::Library Library;
        ms::quic::Registration Registration{Library};
        ms::quic::Settings Settings;
        Settings.SetIdleTimeoutMs(IdleTimeoutMs).SetServerResumptionLevel(QUIC_SERVER_RESUME_AND_ZERORTT).SetPeerBidiStreamCount(1);

        ms::quic::Configuration Configuration{ Registration, {Alpn}, Settings, {*SelfCert} };
        printf("Status %d\n", (QUIC_STATUS)Configuration);
        ms::quic::Listener Listener{Registration};
        QUIC_STATUS Res = Listener.StopOnCleanup().Start({"sample"}, 4567);
        printf("Status %d\n", Res);

        Listener.SetListenerFunc([Configuration](ms::quic::Listener& Listener, QUIC_LISTENER_EVENT* Event) noexcept -> QUIC_STATUS {
            if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
                auto Conn = Listener.GetNewConnection(Event);
                return Conn.SetConnectionFunc(ServerConnectionCallback).SetConfiguration(Configuration);
            }
            return QUIC_STATUS_SUCCESS;
        });

        getchar();
    }

    QuicPlatFreeSelfSignedCert(SelfCert);

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();
}
