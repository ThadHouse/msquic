#include "client.h"

#include "stdio.h"

int main() {
    auto status = QuicChatClientStart("TestServer", "10.0.0.248", nullptr, nullptr);

    printf("Status: %d\n", status);

    printf("Press Enter to exit.\n\n");
    getchar();

    QuicChatClientEnd();
}