#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100) // Unreferenced parameter errcode in inline function
#endif
#include "openssl/err.h"
#include "openssl/ssl.h"
#ifdef _WIN32
#pragma warning(pop)
#endif

#include <thread>
#include <array>

//#define SINGLE_THREADED

int main() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ERR_clear_error();

    auto cb = []() {
        while (true) {
            EVP_KEYEXCH* kx = EVP_KEYEXCH_fetch(NULL, "ECDH", NULL);
            if (kx != NULL) {
                EVP_KEYEXCH_free(kx);
            }
            else {
                char buf[256];
                const char* file;
                int line;
                ERR_error_string_n(ERR_get_error_line(&file, &line), buf, sizeof(buf));
                printf("ERR: %s, file :%s:%d\n", buf, file, line);
            }
        }
    };

#ifdef SINGLE_THREADED
    std::thread thread{ cb };
    thread.join();
#else

    std::array<std::thread, 8> threads;
    for (int i = 0; i < threads.size(); ++i) {
        threads[i] = std::thread{ cb };
    }

    threads[0].join();
#endif
}
