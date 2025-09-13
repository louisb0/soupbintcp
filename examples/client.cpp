#include <soupbin/client.hpp>

#include <cstdlib>
#include <expected>
#include <iostream>
#include <span>
#include <string_view>
#include <system_error>

#include <unistd.h>

int main() {
    auto client = soupbin::connect({
        .hostname = "localhost",
        .port = "8888",
        .username = "user",
        .password = "pass",
        // .session_id = "5cee2d90e1",
        // .sequence_num = "0",
    });

    if (!client) {
        const auto &err = client.error();
        std::cout << "Could not connect - [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    for (int i = 0; i < 5; i++) { // NOLINT
        while (auto msg = client->try_recv_msg()) {
            switch (msg->type) {
            case soupbin::server_message::type::debug:
                std::cout << "Debug: ";
                break;

            case soupbin::server_message::type::unsequenced:
                std::cout << "Unsequenced: ";
                break;

            case soupbin::server_message::type::sequenced:
                std::cout << "Sequenced: ";
                break;
            }

            auto content = std::string_view(reinterpret_cast<const char *>(msg->payload.data()), msg->payload.size());
            std::cout << content << "\n";
        }

        client->queue_unseq_msg(std::as_bytes(std::span("Ping!")));

        if (auto err = client->commit()) {
            std::cout << "Could not commit - [" << err.category().name() << "]: " << err.message() << '\n';
            return EXIT_FAILURE;
        }

        sleep(1);
    }

    if (auto err = client->logout(); err) {
        std::cout << "Could not logout - [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "Press Enter to exit...";
    std::cin.get();
}
