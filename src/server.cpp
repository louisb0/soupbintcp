#include "soupbin/server.hpp"

#include "soupbin/errors.hpp"

#include "detail/assert.hpp"
#include "detail/client_manager.hpp"
#include "detail/log.hpp"
#include "detail/messages.hpp"
#include "detail/partial.hpp"
#include "detail/util.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <system_error>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace soupbin {

// ---------------- declaration ----------------

class server::impl {
    int efd_;
    int lfd_;
    server_config cfg_;

    detail::client_manager client_mgr_;
    std::vector<detail::client *> clients_to_drop_;

public:
    impl(int efd, int lfd, server_config &&cfg) noexcept : efd_(efd), lfd_(lfd), cfg_(std::move(cfg)) {
        ASSERT(efd_ >= 0);
        ASSERT(lfd_ >= 0);
    }

    ~impl() {
        ASSERT(efd_ >= 0);
        ASSERT(lfd_ >= 0);

        close(efd_);
        close(lfd_);
    }

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) = delete;
    impl &operator=(impl &&) = delete;

    // TODO: All errors are currently treated as fatal, e.g. failing to send() a single heartbeat
    // will shutdown the server.
    [[nodiscard]] std::error_code run() noexcept;

private:
    [[nodiscard]] std::error_code handle_client(detail::client *c) noexcept;
    [[nodiscard]] std::error_code handle_unauthenticated(detail::client *c) noexcept;
    [[nodiscard]] std::error_code handle_authenticated(detail::client *c) noexcept;

    [[nodiscard]] std::error_code service_heartbeats() noexcept;
    [[nodiscard]] std::error_code service_client_queue() noexcept;
};

server::server(std::unique_ptr<impl> p) noexcept : impl_(std::move(p)) {}
server::server(server &&other) noexcept : impl_(std::move(other.impl_)) {}
server &server::operator=(server &&) noexcept = default;
server::~server() noexcept = default;

std::error_code server::run() noexcept { return impl_->run(); }

// ---------------- definition ---------------

std::error_code server::impl::run() noexcept {
    // TODO(high-priority): We need to handle the case where a client forceably disconnects between
    // recv(), where we would get an error or 0 bytes, and following sends(), which causes SIGPIPE.
    signal(SIGPIPE, SIG_IGN);

    for (;;) {
        ASSERT(clients_to_drop_.empty());

        std::array<epoll_event, SOUPBIN_S_CLIENTS_PER_TICK> events{};
        int nfds = epoll_wait(efd_, events.data(), events.size(), static_cast<int>(cfg_.tick.count()));
        if (nfds == -1) {
            ASSERT(errno == EINTR);
            continue;
        }

        for (const auto &ev : std::span(events.data(), nfds)) {
            auto *c = static_cast<detail::client *>(ev.data.ptr);

            ASSERT(c != nullptr);
            ASSERT(c->in_use());

            if (auto fatal = handle_client(c); fatal) {
                return fatal;
            }

            c->last_recv = std::chrono::steady_clock::now();
        }

        if (auto fatal = service_heartbeats(); fatal) {
            return fatal;
        }

        if (auto fatal = service_client_queue(); fatal) {
            return fatal;
        }

        if (!clients_to_drop_.empty()) {
            for (auto *c : clients_to_drop_) {
                DEBUG_ASSERT(c != nullptr);
                DEBUG_ASSERT(c->in_use());

                epoll_ctl(efd_, EPOLL_CTL_DEL, c->fd, nullptr);
                close(c->fd);
                client_mgr_.remove(c);
            }

            LOG_INFO("dropped {} client(s).", clients_to_drop_.size());
            clients_to_drop_.clear();
        }
    }
}

std::error_code server::impl::handle_client(detail::client *c) noexcept {
    DEBUG_ASSERT(c->in_use());

    std::error_code fatal;
    if (c->authenticated()) {
        fatal = handle_authenticated(c);
    } else {
        fatal = handle_unauthenticated(c);
    }

    return fatal;
}

std::error_code server::impl::handle_unauthenticated(detail::client *c) noexcept {
    DEBUG_ASSERT(c->in_use());
    DEBUG_ASSERT(!c->authenticated());

    std::array<std::byte, sizeof(detail::msg_login_request)> buffer{};

    // Receive data.
    size_t read = c->partial.load({ buffer.data(), buffer.size() });
    while (read != buffer.size()) {
        ssize_t bytes = recv(c->fd, buffer.data() + read, buffer.size() - read, 0);
        if (bytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }

            LOG_CRITICAL("client(fd={}) failed unauthenticated recv(), added to drop list.", c->fd);
            clients_to_drop_.push_back(c);

            return { errno, std::system_category() };
        }

        if (bytes == 0) {
            LOG_WARN("client(fd={}) disconnected prior to sending their login request, added to drop list.", c->fd);
            clients_to_drop_.push_back(c);

            return {};
        }

        read += bytes;
    }

    // Check for partial.
    if (read != buffer.size()) {
        c->partial.store({ buffer.data(), read });
        return {};
    }

    // Check for expected message type.
    auto *msg = reinterpret_cast<detail::msg_login_request *>(buffer.data());
    if (msg->hdr.type != detail::mt_login_request) {
        LOG_WARN("client(fd={}) login request packet is of wrong message type, added to drop list.", c->fd);
        clients_to_drop_.push_back(c);

        return {};
    }

    LOG_INFO("mt_login_request: client(fd={}) session_id='{}' sequence_num={}",
             c->fd, detail::format_session_id(msg->session_id), detail::format_sequence_num(msg->sequence_num));

    // Authorise or remove the client.
    bool authenticated = cfg_.on_auth(detail::format_username(msg->username), detail::format_password(msg->password));
    if (authenticated) {
        LOG_INFO("mt_login_request: client(fd={}) authenticated", c->fd);
        client_mgr_.authenticate(c);

        detail::msg_login_accepted res = detail::msg_login_accepted::build(msg);
        if (send(c->fd, &res, sizeof(res), 0) == -1) {
            LOG_CRITICAL("client(fd={}) failed to send() msg_login_accepted, added to drop list.", c->fd);
            clients_to_drop_.push_back(c);

            return { errno, std::system_category() };
        }
    } else {
        LOG_WARN("mt_login_request: client(fd={}) is not authenticated, added to drop list.", c->fd);
        clients_to_drop_.push_back(c);

        detail::msg_login_rejected res = detail::msg_login_rejected::build(detail::rej_not_authorised);
        if (send(c->fd, &res, sizeof(res), 0) == -1) {
            LOG_CRITICAL("client(fd={}) failed to send() msg_login_rejected.", c->fd);
            return { errno, std::system_category() };
        }
    }

    return {};
}

std::error_code server::impl::handle_authenticated(detail::client *c) noexcept {
    DEBUG_ASSERT(c->in_use());
    DEBUG_ASSERT(c->authenticated());

    std::array<std::byte, SOUPBIN_S_MESSAGES_PER_CLIENT * detail::max_client_message_size> buffer{};

    // Receive data.
    size_t read = c->partial.load({ buffer.data(), buffer.size() });
    while (read != buffer.size()) {
        ssize_t bytes = recv(c->fd, buffer.data() + read, buffer.size() - read, 0);
        if (bytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }

            if (errno == ECONNRESET || errno == ECONNABORTED || errno == EPIPE) {
                LOG_INFO("client(fd={}) disconnected abruptly ({}), added to drop list.", c->fd, strerror(errno));
                clients_to_drop_.push_back(c);

                break;
            }

            LOG_CRITICAL("client(fd={}) failed authenticated recv(), added to drop list.", c->fd);
            clients_to_drop_.push_back(c);

            return { errno, std::system_category() };
        }

        if (bytes == 0) {
            LOG_INFO("client(fd={}) closed their connection, added to drop list.", c->fd);
            clients_to_drop_.push_back(c);

            break;
        }

        read += bytes;
    }

    // Parse messages.
    std::span<std::byte> window{ buffer.data(), read };
    while (!window.empty()) {
        if (sizeof(detail::msg_header) > window.size()) {
            break;
        }

        const auto *hdr = reinterpret_cast<const detail::msg_header *>(window.data());
        size_t payload_size = ntohs(hdr->length);
        size_t total_msg_size = sizeof(detail::msg_header) + payload_size;

        if (total_msg_size > window.size()) {
            break;
        }

        switch (hdr->type) {
        case detail::mt_debug: {
            auto *msg = reinterpret_cast<detail::msg_debug *>(window.data());
            cfg_.on_debug({ msg->data, ntohs(msg->hdr.length) });
            break;
        }

        case detail::mt_client_heartbeat: {
            // NOTE: This is handled implicitly by setting last_recv on any data.
            break;
        }

        case detail::mt_unsequenced:
            // TODO
        case detail::mt_logout_request:
            // TODO
        case detail::mt_login_accepted:
        case detail::mt_login_rejected:
        case detail::mt_sequenced:
        case detail::mt_server_heartbeat:
        case detail::mt_end_of_session:
        case detail::mt_login_request: {
            // TODO: Consider dropping the client.
            LOG_WARN("client(fd={}) sent unexpected message type (mt={})", c->fd, static_cast<char>(hdr->type));
            break;
        }

        default: {
            // TODO: Consider dropping the client.
            LOG_WARN("client(fd={}) sent unknown message type (mt={})", c->fd, static_cast<char>(hdr->type));
            break;
        }
        }

        window = window.subspan(total_msg_size);
    }

    if (!window.empty()) {
        c->partial.store(window);
    }

    return {};
}

std::error_code server::impl::service_heartbeats() noexcept {
    const detail::msg_server_heartbeat msg = detail::msg_server_heartbeat::build();
    const auto now = std::chrono::steady_clock::now();

    for (detail::client *c : client_mgr_.authenticated()) {
        DEBUG_ASSERT(c->in_use());
        ASSERT(c->authenticated());

        if (now - c->last_recv >= std::chrono::seconds(SOUPBIN_S_CLIENT_HEARTBEAT_SEC)) {
            LOG_INFO("client(fd={}) failed heartbeat check", c->fd);
            clients_to_drop_.push_back(c);

            continue;
        }

        // TODO: Profile batching. Note the introduction of (optional) complexity around sending a heartbeat
        // to a client we decided to drop in the above portion of the loop.
        if (now - c->last_send >= std::chrono::seconds(SOUPBIN_S_SERVER_HEARTBEAT_SEC - 1)) {
            LOG_DEBUG("client(fd={}) sending heartbeat", c->fd);

            if (send(c->fd, &msg, sizeof(msg), 0) == -1) {
                LOG_CRITICAL("client(fd={}) failed to send() msg_server_heartbeat, added to drop list.", c->fd);
                clients_to_drop_.push_back(c);

                return { errno, std::system_category() };
            }

            c->last_send = now;
        }
    }

    return {};
}

std::error_code server::impl::service_client_queue() noexcept {
    sockaddr_in addr{};
    socklen_t addrlen = sizeof(addr);

    for (size_t i = 0; i < SOUPBIN_S_NEW_CLIENTS_PER_TICK; i++) {
        int fd = accept4(lfd_, reinterpret_cast<sockaddr *>(&addr), &addrlen, O_NONBLOCK);
        if (fd == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                break;
            }

            return { errno, std::system_category() };
        }

        detail::client *c = client_mgr_.add(fd);

        epoll_event ev{ .events = EPOLLIN, .data = { .ptr = c } };
        if (epoll_ctl(efd_, EPOLL_CTL_ADD, fd, &ev) == -1) {
            LOG_INFO("client(fd={}) failed to epoll_ctl(EPOLL_CTL_ADD), dropping.", fd);
            close(c->fd);
            client_mgr_.remove(c);

            return { errno, std::system_category() };
        }

        LOG_INFO("client(fd={}) accepted", fd);
    }

    return {};
}

// ----------------- factory -----------------

std::expected<server, std::error_code> make_server(server_config cfg) {
    if (cfg.hostname.empty()) {
        return std::unexpected(make_soupbin_error(errc::bad_hostname));
    }

    if (cfg.port.empty()) {
        return std::unexpected(make_soupbin_error(errc::bad_port));
    }

    // Resolve address.
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    addrinfo *res{};
    int gai_c = getaddrinfo(cfg.hostname.c_str(), cfg.port.c_str(), &hints, &res);
    if (gai_c != 0) {
        LOG_CRITICAL("Failed to getaddrinfo() for the provided hostname and port.");

        if (gai_c == EAI_SYSTEM) {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }

        return std::unexpected(make_gai_error(gai_c));
    }

    // Find a suitable binding address.
    int lfd = -1;
    for (addrinfo *it = res; it != nullptr; it = it->ai_next) {
        int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == -1) {
            continue;
        }

        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
            close(fd);
            continue;
        }

        if (bind(fd, it->ai_addr, it->ai_addrlen) == -1) {
            close(fd);
            continue;
        }

        if (listen(fd, SOMAXCONN) == -1) {
            close(fd);
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(fd);
            continue;
        }

        lfd = fd;
        break;
    }

    freeaddrinfo(res);

    if (lfd == -1) {
        return std::unexpected(make_soupbin_error(errc::bad_host));
    }

    // Create epoll instance and server.
    int efd = epoll_create1(0);
    if (efd == -1) {
        LOG_CRITICAL("Failed to create epoll instance with epoll_create1().");
        detail::preserving_close(lfd);

        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    return server(std::make_unique<server::impl>(efd, lfd, std::move(cfg)));
}

} // namespace soupbin
