/*
 * Minimal shim for android-base/scopeguard.h
 */

#pragma once

#include <functional>
#include <utility>

namespace android {
namespace base {

template <typename F>
class ScopeGuard {
public:
    explicit ScopeGuard(F&& f) : f_(std::forward<F>(f)), active_(true) {}

    ScopeGuard(ScopeGuard&& other) noexcept
        : f_(std::move(other.f_)), active_(other.active_) {
        other.active_ = false;
    }

    ~ScopeGuard() {
        if (active_) f_();
    }

    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;
    ScopeGuard& operator=(ScopeGuard&&) = delete;

    void Disable() { active_ = false; }

private:
    F f_;
    bool active_;
};

template <typename F>
ScopeGuard<F> make_scope_guard(F&& f) {
    return ScopeGuard<F>(std::forward<F>(f));
}

}  // namespace base
}  // namespace android
