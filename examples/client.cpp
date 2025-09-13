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
        .password = "letmein",
        // .session_id = "5cee2d90e1",
        // .sequence_num = "0",
    });

    if (!client) {
        const auto &err = client.error();
        std::cout << "Could not connect - [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    while (true) {
        client->queue_unseq_msg(std::as_bytes(std::span("ping")));

        while (auto msg = client->try_recv_msg()) {
            switch (msg->type) {
            case soupbin::message::type::debug:
                std::cout << "Debug: ";
                break;

            case soupbin::message::type::unsequenced:
                std::cout << "Unsequenced: ";
                break;

            case soupbin::message::type::sequenced:
                std::cout << "Sequenced: ";
                break;
            }

            auto content = std::string_view(reinterpret_cast<const char *>(msg->payload.data()), msg->payload.size());
            std::cout << content << "\n";
        }

        if (auto err = client->commit()) {
            std::cout << "Could not commit - [" << err.category().name() << "]: " << err.message() << '\n';
            return EXIT_FAILURE;
        }

        sleep(1);
    }
}
