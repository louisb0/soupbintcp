#pragma once

#include <chrono>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace soupbin {

#ifndef SOUPBIN_S_NEW_CLIENTS_PER_TICK
#define SOUPBIN_S_NEW_CLIENTS_PER_TICK 4
#endif

#ifndef SOUPBIN_S_CLIENTS_PER_TICK
#define SOUPBIN_S_CLIENTS_PER_TICK 16
#endif

#ifndef SOUPBIN_S_MESSAGES_PER_CLIENT
#define SOUPBIN_S_MESSAGES_PER_CLIENT 8
#endif

#ifndef SOUPBIN_S_CLIENT_HEARTBEAT_SEC
#define SOUPBIN_S_CLIENT_HEARTBEAT_SEC 5
#endif

#ifndef SOUPBIN_S_SERVER_HEARTBEAT_SEC
#define SOUPBIN_S_SERVER_HEARTBEAT_SEC 15
#endif

// NOTE: The server is single-threaded. It is expected for these to be non-blocking and
// for tick_handler to be the most compute intensive callback.
using auth_handler = std::function<bool(std::string_view, std::string_view)>;
using debug_handler = std::function<void(std::span<const std::byte>)>;
using data_handler = std::function<void(std::span<const std::byte>)>;
using tick_handler = std::function<bool()>;

struct server_config {
    std::string hostname;
    std::string port;
    std::chrono::milliseconds tick{ 0 };

    auth_handler on_auth;
    data_handler on_data;
    debug_handler on_debug;
    tick_handler on_tick;
};

class server {
public:
    server(server &&) noexcept;
    server &operator=(server &&) noexcept;
    server(const server &) = delete;
    server &operator=(const server &) = delete;
    ~server() noexcept;

    [[nodiscard]] std::error_code run() noexcept;

private:
    class impl;
    std::unique_ptr<impl> impl_;

    explicit server(std::unique_ptr<impl> p) noexcept;
    friend std::expected<server, std::error_code> make_server(server_config);
};

[[nodiscard]] std::expected<server, std::error_code> make_server(server_config);

} // namespace soupbin
