#include <soupbin/server.hpp>

#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <expected>
#include <iostream>
#include <span>
#include <string_view>

bool handle_auth(std::string_view username, std::string_view password) {
    (void)username;
    return password == "letmein";
}

void handle_unseq_msg(soupbin::response res, std::span<const std::byte> msg) {
    std::cout << "Unsequenced: " << std::string_view(reinterpret_cast<const char *>(msg.data()), msg.size()) << '\n';

    res.queue_seq_msg(std::as_bytes(std::span("Pong!")));
}

void handle_debug(std::span<const std::byte> msg) {
    std::cout << "Debug: " << std::string_view(reinterpret_cast<const char *>(msg.data()), msg.size()) << '\n';
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
        .on_unseq_msg = handle_unseq_msg,
        .on_debug = handle_debug,
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
