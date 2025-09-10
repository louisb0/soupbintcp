#include <soupbin/client.hpp>

#include <cstdlib>
#include <expected>
#include <iostream>
#include <span>
#include <string>
#include <system_error>

#include <unistd.h>

int main() {
    auto client = soupbin::connect({
        .hostname = "localhost",
        .port = "8888",
        .username = "user",
        .password = "letmein",
        // .session_id = "abc123",
        // .sequence_num = "1293874",
    });

    if (!client) {
        const auto &err = client.error();
        std::cout << "Could not connect - [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    while (true) {
        client->queue_debug_msg(std::as_bytes(std::span("ping")));

        while (auto msg = client->try_recv_msg()) {
            std::cout << "Received: " << std::string(reinterpret_cast<const char *>(msg->data()), msg->size()) << "\n";
        }

        if (auto err = client->service()) {
            std::cout << "Could not service - [" << err.category().name() << "]: " << err.message() << '\n';
            return EXIT_FAILURE;
        }

        sleep(1);
    }
}
