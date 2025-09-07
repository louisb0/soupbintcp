#pragma once

#include <cassert>
#include <source_location>

#include <spdlog/spdlog.h>

#define ASSERT_UNREACHABLE()                                                                    \
    do {                                                                                        \
        auto loc = std::source_location::current();                                             \
        spdlog::critical("[{}:{}] Unreachable location hit.", loc.function_name(), loc.line()); \
        std::abort();                                                                           \
    } while (0)

#define ASSERT(condition)                                                                  \
    do {                                                                                   \
        if (!(condition)) [[unlikely]] { /* NOLINT(readability-simplify-boolean-expr) */   \
            auto loc = std::source_location::current();                                    \
            spdlog::critical("[{}:{}] Assertion failed: " #condition, loc.function_name(), \
                             loc.line());                                                  \
            std::abort();                                                                  \
        }                                                                                  \
    } while (0)

#ifdef NDEBUG
#define DEBUG_ASSERT(condition) ((void)0)
#else
#define DEBUG_ASSERT(condition) ASSERT(condition)
#endif
