#include "soupbin/server.hpp"

#include "soupbin/errors.hpp"

#include "detail/assert.hpp"

#include <system_error>

#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>

namespace soupbin {

// ---------------- declaration ----------------

class server::impl {
    int efd_;
    int lfd_;
    server_config cfg_;

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
};

server::server(std::unique_ptr<impl> p) noexcept : impl_(std::move(p)) {}
server::server(server &&other) noexcept : impl_(std::move(other.impl_)) {}
server &server::operator=(server &&) noexcept = default;
server::~server() noexcept = default;

std::error_code server::run() noexcept { return impl_->run(); }

// ---------------- definition ---------------

std::error_code server::impl::run() noexcept { return {}; }

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
        close(efd);

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
        close(efd);
        return std::unexpected(make_soupbin_error(errc::bad_host));
    }

    // Create server.
    return server(std::make_unique<server::impl>(efd, lfd, std::move(cfg)));
}

} // namespace soupbin
