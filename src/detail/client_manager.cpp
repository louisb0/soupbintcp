#include "client_manager.hpp"

#include "detail/assert.hpp"

#include <cstddef>
#include <span>
#include <utility>

namespace soupbin::detail {

client *client_manager::add(int fd) noexcept {
    ASSERT(!store_.contains(fd));

    auto now = std::chrono::steady_clock::now();
    auto [it, ok] = store_.emplace(fd, client{ .fd = fd, .last_recv = now, .last_send = now });
    ASSERT(ok);

    return &it->second;
}

void client_manager::authenticate(client *c) noexcept {
    ASSERT(c->in_use());
    ASSERT(!c->authenticated());
    ASSERT(&store_[c->fd] == c);

    c->auth_index = static_cast<int>(authenticated_.size());
    authenticated_.push_back(c);
}

void client_manager::remove(client *c) noexcept {
    ASSERT(c->in_use());
    ASSERT(&store_[c->fd] == c);

    if (c->authenticated()) {
        ASSERT(c->auth_index >= 0);
        ASSERT(static_cast<size_t>(c->auth_index) < authenticated_.size());
        ASSERT(authenticated_[c->auth_index] == c);

        client *tail = authenticated_.back();

        authenticated_[c->auth_index] = tail;
        tail->auth_index = c->auth_index;

        authenticated_.pop_back();
        c->auth_index = -1;
    }

    store_.erase(c->fd);
}

std::span<client *> client_manager::authenticated() noexcept {
#ifndef NDEBUG
    for (const auto *c : authenticated_) {
        DEBUG_ASSERT(c->in_use());
        DEBUG_ASSERT(c->authenticated());
        DEBUG_ASSERT(c->auth_index >= 0);
        DEBUG_ASSERT(static_cast<size_t>(c->auth_index) < authenticated_.size());
        DEBUG_ASSERT(authenticated_[c->auth_index] == c);
    }
#endif

    return { authenticated_.data(), authenticated_.size() };
}

} // namespace soupbin::detail
