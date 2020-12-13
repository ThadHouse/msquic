#pragma once

// TODO make this include wdm.h instead
#include <Windows.h>

namespace std {
class atomic_int {
public:
    // Non movable, non copyable
    constexpr atomic_int(int Desired) noexcept : Value{Desired} {}
    atomic_int(const atomic_int&) = delete;
    atomic_int& operator=(const atomic_int&) = delete;
    atomic_int(atomic_int&&) = delete;
    atomic_int& operator=(atomic_int&&) = delete;

    int fetch_add(int Arg) noexcept {
        return InterlockedExchangeAdd(&reinterpret_cast<volatile LONG&>(Value), Arg);
    }

    int fetch_sub(int Arg) noexcept {
        return fetch_add(-Arg);
    }
private:
    int Value;
};
}
