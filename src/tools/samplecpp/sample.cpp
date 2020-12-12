#include <msquiccpp.h>
#define QUIC_TEST_APIS 1
#include <quic_platform.h>

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

int main() {
    QuicPlatformSystemLoad();
    QuicPlatformInitialize();

    auto SelfCert = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);

    {
        ms::quic::Library Library;
        ms::quic::Registration Registration{Library};
        ms::quic::Configuration Configuration{Registration, {"sample"}};
        QUIC_STATUS Res = Configuration.LoadCredential(*SelfCert);
        printf("Status %d\n", Res);
        ms::quic::Listener Listener{Registration};
        Res = Listener.Start({"sample"}, 4567);
        printf("Status %d\n", Res);

        Listener.SetListenerFunc([Configuration](const QUIC_NEW_CONNECTION_INFO&, ms::quic::Connection& Conn) noexcept -> QUIC_STATUS {
            Conn.SetConnectionFunc([Conn](QUIC_CONNECTION_EVENT* Event) noexcept -> QUIC_STATUS {
                printf("Received Event Type: %d\n", Event->Type);
                // Use Conn or Event in here
                UNREFERENCED_PARAMETER(Conn);
                return QUIC_STATUS_SUCCESS;
            });
            return Conn.SetConfiguration(Configuration);
        });

        getchar();
        Listener.Stop();
    }

    QuicPlatFreeSelfSignedCert(SelfCert);

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();
}
