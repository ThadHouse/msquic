#pragma once

// TODO make this include wdm.h instead
#include <Windows.h>
#include <cstddef>

namespace stdkm {
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

template<class T> struct remove_reference {typedef T type;};
template<class T> struct remove_reference<T&> {typedef T type;};
template<class T> struct remove_reference<T&&> {typedef T type;};
template<class T>
using remove_reference_t = typename remove_reference<T>::type;

template<class T>
constexpr stdkm::remove_reference_t<T>&& move(T&& t) noexcept {
    return static_cast<typename stdkm::remove_reference<T>::type&&>(t);
}

template<typename>
class function;

template<typename ReturnValue, typename... Args>
class function<ReturnValue(Args...)> {
public:

    function() noexcept {}
    function(nullptr_t) noexcept {}

    template<typename T>
    function(T f) noexcept : callable{new CallableT<T>(stdkm::move(f))} {
    }

    explicit operator bool() const noexcept {
        return callable != nullptr;
    }

    ReturnValue operator()(Args... args) const {
        return callable->Invoke(args...);
    }
private:
    class FCallable {
    public:
        virtual ~FCallable() = default;
        virtual ReturnValue Invoke(Args...) = 0;
    };

    template<typename T>
    class CallableT : public FCallable {
    public:
        CallableT(T t) : t_{stdkm::move(t)} {}
        ~CallableT() override = default;
        ReturnValue Invoke(Args... args) override {
            return t_(args...);
        }
    private:
        T t_;
    };

    FCallable* callable{nullptr};
};

}
