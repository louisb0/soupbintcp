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
#include <system_error>
#include <utility>

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

    [[nodiscard]] std::error_code run() noexcept;

private:
    [[nodiscard]] std::error_code handle_unauthenticated(detail::client *c) noexcept;
    [[nodiscard]] std::error_code handle_authenticated(detail::client *c) noexcept;
    [[nodiscard]] std::error_code accept_n_clients(size_t n_clients) noexcept;

    void drop_client(detail::client *c) noexcept;
};

server::server(std::unique_ptr<impl> p) noexcept : impl_(std::move(p)) {}
server::server(server &&other) noexcept : impl_(std::move(other.impl_)) {}
server &server::operator=(server &&) noexcept = default;
server::~server() noexcept = default;

std::error_code server::run() noexcept { return impl_->run(); }

// ---------------- definition ---------------

std::error_code server::impl::run() noexcept {
    for (;;) {
        std::array<epoll_event, SOUPBIN_CLIENTS_PER_TICK> events{};
        int nfds = epoll_wait(efd_, events.data(), events.size(), static_cast<int>(cfg_.tick.count()));
        if (nfds == -1) {
            ASSERT(errno == EINTR);
            continue;
        }

        for (const auto &ev : std::span(events.data(), nfds)) {
            auto *c = static_cast<detail::client *>(ev.data.ptr);

            auto err = c->authenticated() ? handle_authenticated(c) : handle_unauthenticated(c);
            if (err) {
                return err;
            }
        }

        if (auto err = accept_n_clients(SOUPBIN_NEW_CLIENTS_PER_TICK); err) {
            return err;
        }
    }
}

std::error_code server::impl::handle_unauthenticated(detail::client *c) noexcept {
    std::array<std::byte, sizeof(detail::msg_login_request)> buffer{};

    // Receive data.
    size_t read = c->partial.load({ buffer.data(), buffer.size() });
    while (read != buffer.size()) {
        ssize_t bytes = recv(c->fd, buffer.data() + read, buffer.size() - read, 0);
        if (bytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }

            // TODO: Categorise errors by fatal and transient.
            LOG_CRITICAL("could not recv unauthenticated client");
            return { errno, std::system_category() };
        }

        if (bytes == 0) {
            drop_client(c);
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
        drop_client(c);
        return {};
    }

    // Authorise or remove the client.
    bool authorised = cfg_.on_auth(msg->sv_username(), msg->sv_password());
    if (authorised) {
        client_mgr_.authenticate(c);
        LOG_INFO("authenticated client fd={}", c->fd);

        detail::msg_login_accepted res = detail::msg_login_accepted::build(msg);
        if (send(c->fd, &res, sizeof(res), 0) == -1) {
            drop_client(c);
            LOG_CRITICAL("could not send msg_login_accepted");
            return { errno, std::system_category() };
        }
    } else {
        drop_client(c);
        LOG_INFO("removed unauthenticated client fd={}", c->fd);

        detail::msg_login_rejected res = detail::msg_login_rejected::build(detail::rej_not_authorised);
        if (send(c->fd, &res, sizeof(res), 0) == -1) {
            LOG_CRITICAL("could not send msg_login_rejected");
            return { errno, std::system_category() };
        }
    }

    return {};
}

std::error_code server::impl::handle_authenticated(detail::client *c) noexcept {
    return {};
}

std::error_code server::impl::accept_n_clients(size_t n_clients) noexcept {
    sockaddr_in addr{};
    socklen_t addrlen = sizeof(addr);

    for (size_t i = 0; i < n_clients; i++) {
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
            drop_client(c);
            return { errno, std::system_category() };
        }

        LOG_INFO("accepted client fd={}", fd);
    }

    return {};
}

void server::impl::drop_client(detail::client *c) noexcept {
    epoll_ctl(efd_, EPOLL_CTL_DEL, c->fd, nullptr);
    close(c->fd);
    client_mgr_.remove(c);
}

// ----------------- factory -----------------

std::expected<server, std::error_code> make_server(server_config cfg) {
    if (cfg.hostname.empty()) {
        return std::unexpected(make_soupbin_error(errc::bad_hostname));
    }

    if (cfg.port.empty()) {
        return std::unexpected(make_soupbin_error(errc::bad_port));
    }

    // Create epoll instance.
    int efd = epoll_create1(0);
    if (efd == -1) {
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // Resolve address.
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    addrinfo *res{};
    int gai_c = getaddrinfo(cfg.hostname.c_str(), cfg.port.c_str(), &hints, &res);
    if (gai_c != 0) {
        detail::preserving_close(efd);

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
        detail::preserving_close(efd);
        return std::unexpected(make_soupbin_error(errc::bad_host));
    }

    // Create server.
    return server(std::make_unique<server::impl>(efd, lfd, std::move(cfg)));
}

} // namespace soupbin
