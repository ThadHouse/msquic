#pragma once

#include "msquic.h"

#include <atomic>

namespace ms::quic {
class Registration;
class Connection;
class Stream;
class Library;

namespace detail {
    inline constexpr const QUIC_API_TABLE* GetApiTableFromLibrary(const Library&);
}

template <class T>
class Base {
private:
protected:
    struct BaseDataStore {
        std::atomic_int RefCount{1};
        QUIC_STATUS InitStatus;
    };
public:
    operator QUIC_STATUS() const noexcept {
        const T* Inst = static_cast<const T*>(this);
        if (Inst->Storage) return Inst->Storage->InitStatus;
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    operator bool() const noexcept {
        return QUIC_SUCCEEDED((QUIC_STATUS)*static_cast<const T*>(this));
    }

    operator const QUIC_API_TABLE*() const noexcept {
        return GetTable();
    }

    constexpr const QUIC_API_TABLE* GetTable() const noexcept {
        return detail::GetApiTableFromLibrary(static_cast<const T*>(this)->Storage->Library);
    }
protected:
    void AddRef() noexcept {
        static_cast<T*>(this)->Storage->RefCount.fetch_add(1);
    }
    bool Release() noexcept {
        if (static_cast<T*>(this)->Storage) {
            return static_cast<T*>(this)->Storage->RefCount.fetch_sub(1) == 0;
        }
        // Return false if already deleted
        return false;
    }
};

class Library : public Base<Library> {
private:
    struct DataStore : public Base<Library>::BaseDataStore {

    };
public:
    Library() noexcept {
        Storage = new(std::nothrow) DataStore{};
        if (Storage == nullptr) return;
        Storage->InitStatus = MsQuicOpen(&ApiTable);
    }
    ~Library() noexcept {
        Close();
    }

    Library(const Library& Other) noexcept {
        Storage = Other.Storage;
        AddRef();
    }

    Library& operator=(const Library& Other) noexcept {
        Close();

        Storage = Other.Storage;
        AddRef();
    }

    Library(Library&& Other) noexcept {
        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    Library& operator=(Library&& Other) noexcept {
        Close();

        Storage = Other.Storage;
        Other.Storage = nullptr;
    }



    inline Registration CreateRegistration() noexcept;

    // }
private:
    void Close() noexcept {
        if (Release()) {
            if (ApiTable) {
                MsQuicClose(ApiTable);
            }
            delete Storage;
            Storage = nullptr;
        }
    }
    // const QUIC_API_TABLE* GetBaseTable() const noexcept {
    //     return ApiTable;
    // }

    DataStore* Storage {nullptr};
    const QUIC_API_TABLE* ApiTable {nullptr};
    friend class Base<Library>;
    friend constexpr const QUIC_API_TABLE* detail::GetApiTableFromLibrary(const Library& Library);

};

namespace detail {
    inline constexpr const QUIC_API_TABLE* GetApiTableFromLibrary(const Library& Library) {
        return Library.ApiTable;
    }
}

class Registration : Base<Registration> {
private:
    struct DataStore: public Base<Registration>::BaseDataStore {
        DataStore(const Library& Lib) noexcept : Library{Lib} {
            InitStatus = Library;
        }
        HQUIC Registration {nullptr};
        Library Library;
    };
public:
    explicit Registration(const Library& Lib) noexcept {
        Storage = new(std::nothrow) DataStore{Lib};
        if (!*this) return;
        Storage->InitStatus = GetTable()->RegistrationOpen(nullptr, &Storage->Registration);
    }

private:

    DataStore* Storage {nullptr};
    friend class Base<Registration>;
};

// class Registration {
// private:
//     struct DataStore {
//         DataStore(const Library Lib) noexcept : Library{Lib} {
//             InitStatus = Library;
//         }
//         QUIC_STATUS InitStatus;
//         Library Library;
//         std::atomic_int ReferenceCount {1};
//     };
// public:
//     Registration(const Library& Lib) : Library{Lib} {
//         if (!Library) {
//             InitStatus = Library;
//             return;
//         }
//     }
// private:
//     Library Library;
// };
}
