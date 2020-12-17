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

// size in pointers of std::function and std::any (roughly 3 pointers larger than std::string when building debug)
constexpr int _Small_object_num_ptrs = 6 + 16 / sizeof(void*);

constexpr size_t _Space_size = (_Small_object_num_ptrs - 1) * sizeof(void*);

template<typename ReturnValue, typename... Args>
class function<ReturnValue(Args...)> {
public:

    function() noexcept {
        Set(nullptr);
    }
    function(nullptr_t) noexcept {
        Set(nullptr);
    }

    template<typename T>
    function(T f) noexcept {
        static_assert(sizeof(T) <= _Space_size, "This MUST be Small optimized");
        Set(::new (static_cast<void*>(&_Mystorage)) CallableT(stdkm::move(f)));
    }

    function(const function&) = delete;
    function& operator=(const function&) = delete;

    function(function&& other) noexcept {
        if (other.Empty()) {
            Set(nullptr);
        } else {
            ResetMove(stdkm::move(other));
        }
    };

    function& operator=(function&& other) noexcept {
        if (this != &other) {
            Tidy();
            if (other.Empty()) {
                Set(nullptr);
            } else {
                ResetMove(stdkm::move(other));
            }
        }
        return *this;
    }

    ~function() noexcept {
        if (!Empty()) {
            Get()->~FCallable();
        }
    }

    explicit operator bool() const noexcept {
        return Get() != nullptr;
    }

    ReturnValue operator()(Args... args) const {
        return Get()->Invoke(args...);
    }
private:
    class FCallable {
    public:
        virtual ~FCallable() = default;
        virtual FCallable* Move(void* Storage) noexcept = 0;
        virtual ReturnValue Invoke(Args...) = 0;
    };

    template<typename T>
    class CallableT : public FCallable {
    public:
        CallableT(T t) : t_{stdkm::move(t)} {}

        CallableT(const CallableT& t) = delete;
        CallableT& operator=(const CallableT& t) = delete;
        // CallableT(CallableT&& t) noexcept {
        //     t_ = stdkm::move(t.t_);
        // }
        // CallableT& operator=(CallableT&& t) noexcept {
        //     if (this != &t) {
        //         t_ = stdkm::move(t.t_);
        //     }
        //     return *this;
        // }

        FCallable* Move(void* Storage) noexcept override {
            const auto Ptr = static_cast<CallableT*>(Storage);
            ::new(const_cast<void*>(static_cast<const volatile void*>(Ptr))) CallableT(stdkm::move(t_));
            return Ptr;
        }

        ~CallableT() override = default;
        ReturnValue Invoke(Args... args) override {
            return t_(args...);
        }
    private:
        T t_;
    };

    // Taken from Microsoft STL
    union _Storage { // storage for small objects (basic_string is small)
        max_align_t _Dummy1; // for maximum alignment
        char _Dummy2[_Space_size]; // to permit aliasing
        FCallable* _Ptrs[_Small_object_num_ptrs]; // _Ptrs[_Small_object_num_ptrs - 1] is reserved
    };

    FCallable* Get() const noexcept {
        return _Mystorage._Ptrs[_Small_object_num_ptrs - 1];
    }

    _Storage _Mystorage;

    void ResetMove(function&& other) noexcept {
        if (!other.Empty()) {
            Set(other.Get()->Move(&_Mystorage));
            other.Tidy();
        }
    }

    bool Empty() const noexcept {
        return Get() == nullptr;
    }

    void Tidy() noexcept {
        if (!Empty()) { // Destroy callable
            Get()->~FCallable();
            Set(nullptr);
        }
    }

    void Set(FCallable* _Ptr) noexcept {
        _Mystorage._Ptrs[_Small_object_num_ptrs - 1] = _Ptr;
    }
};

}
