#include <soupbin/server.hpp>

#include <chrono>
#include <cstdlib>
#include <expected>
#include <iostream>
#include <span>
#include <string_view>

bool handle_auth(std::string_view username, std::string_view password) {
    (void)username;
    return password == "pass";
}

void handle_msg(soupbin::response res, soupbin::client_message msg) {
    switch (msg.type) {
    case soupbin::client_message::type::debug:
        std::cout << "Debug: ";
        break;

    case soupbin::client_message::type::unsequenced:
        std::cout << "Unsequenced: ";
        break;
    }

    auto content = std::string_view(reinterpret_cast<const char *>(msg.payload.data()), msg.payload.size());
    std::cout << content << "\n";

    res.queue_seq_msg(std::as_bytes(std::span("Pong!")));
}

bool handle_tick() {
    return true;
}

int main() {
    auto server = soupbin::make_server({
        .hostname = "localhost",
        .port = "8888",
        .tick = std::chrono::milliseconds(1),
        .on_auth = handle_auth,
        .on_msg = handle_msg,
        .on_tick = handle_tick,
    });

    if (!server) {
        const auto &err = server.error();
        std::cerr << "Could not create server - [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    auto result = server->run();
    if (result) {
        std::cerr << "Server stopped with error - [" << result.category().name() << "]: " << result.message() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
