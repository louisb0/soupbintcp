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
#include <vector>

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

namespace detail {
    class session;
}
class response;

struct client_message {
    enum class type : uint8_t {
        debug,
        unsequenced,
    } type;
    std::span<const std::byte> payload;
};

using auth_handler = std::function<bool(std::string_view, std::string_view)>;
using msg_handler = std::function<void(soupbin::response, client_message)>;
using tick_handler = std::function<bool()>;

struct server_config {
    std::string hostname;
    std::string port;
    std::chrono::milliseconds tick{ 0 };

    auth_handler on_auth;
    msg_handler on_msg;
    tick_handler on_tick;
};

class response {
public:
    void queue_unseq_msg(std::span<const std::byte>) noexcept;
    void queue_seq_msg(std::span<const std::byte>) noexcept;

private:
    friend class server;

    detail::session *session_;
    std::vector<std::byte> *unseq_buffer_;

    response(detail::session *s, std::vector<std::byte> *buf) noexcept : session_(s), unseq_buffer_(buf) {}
};

class server {
public:
    server(const server &) = delete;
    server &operator=(const server &) = delete;
    server(server &&) noexcept;
    server &operator=(server &&) noexcept;
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
