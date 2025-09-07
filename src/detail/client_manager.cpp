#include "client_manager.hpp"

#include "detail/assert.hpp"

#include <cstddef>
#include <utility>

namespace soupbin::detail {

client *client_manager::add(int fd) noexcept {
    auto [it, ok] = store_.emplace(fd, client{ .fd = fd });
    ASSERT(ok);
    return &it->second;
}

void client_manager::authenticate(client *c) noexcept {
    ASSERT(c->in_use());
    ASSERT(!c->authenticated());

    c->auth_index = static_cast<int>(authenticated_.size());
    authenticated_.push_back(c);
}

void client_manager::remove(client *c) noexcept {
    ASSERT(c->in_use());

    if (c->authenticated()) {
        ASSERT(c->auth_index >= 0);
        ASSERT(static_cast<size_t>(c->auth_index) < authenticated_.size());

        client *tail = authenticated_.back();
        authenticated_[c->auth_index] = tail;
        tail->auth_index = c->auth_index;
        authenticated_.pop_back();

        c->auth_index = -1;
    }

    store_.erase(c->fd);
}

} // namespace soupbin::detail
