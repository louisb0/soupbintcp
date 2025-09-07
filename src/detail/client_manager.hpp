#pragma once

#include "detail/partial.hpp"

#include <unordered_map>
#include <vector>

namespace soupbin::detail {

struct client {
    int fd{ -1 };
    int auth_index{ -1 };
    detail::partial partial{};

    [[nodiscard]] bool in_use() const noexcept {
        return fd != -1;
    }

    [[nodiscard]] bool authenticated() const noexcept {
        return auth_index != -1;
    }
};

class client_manager {
    std::unordered_map<int, client> store_;
    std::vector<client *> authenticated_;

public:
    [[nodiscard]] client *add(int cfd) noexcept;
    void authenticate(client *c) noexcept;
    void remove(client *c) noexcept;
};

} // namespace soupbin::detail
