#pragma once

#include "msquic.h"

#include <atomic>
#include <string>

namespace ms::quic {
class Registration;
class Connection;
class Stream;
class Library;
class Configuration;

template <class T>
class Base {
private:
protected:
    struct BaseDataStore {
        std::atomic_int RefCount{1};
        QUIC_STATUS InitStatus;
    };
    const QUIC_API_TABLE* ApiTable {nullptr};

    explicit Base(const QUIC_API_TABLE* Table) noexcept : ApiTable{Table} {
    }

    Base(const Base& Other) noexcept {
        ApiTable = Other.ApiTable;
    }

    Base(Base&& Other) noexcept {
        ApiTable = Other.ApiTable;
    }

    Base& operator=(const Base& Other) noexcept {
        ApiTable = Other.ApiTable;
    }

    Base& operator=(Base&& Other) noexcept {
        ApiTable = Other.ApiTable;
    }
public:
    constexpr operator QUIC_STATUS() const noexcept {
        const T* Inst = static_cast<const T*>(this);
        if (Inst->Storage) return Inst->Storage->InitStatus;
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    constexpr operator bool() const noexcept {
        return QUIC_SUCCEEDED((QUIC_STATUS)*static_cast<const T*>(this));
    }

    constexpr operator const QUIC_API_TABLE*() const noexcept {
        return ApiTable;
    }

    constexpr const QUIC_API_TABLE* GetTable() const noexcept {
        return ApiTable;
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
    Library() noexcept : Base{nullptr} {
        Storage = new(std::nothrow) DataStore{};
        if (Storage == nullptr) return;
        Storage->InitStatus = MsQuicOpen(&ApiTable);
    }
    ~Library() noexcept {
        Close();
    }

    Library(const Library& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        AddRef();
    }

    Library& operator=(const Library& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        AddRef();
    }

    Library(Library&& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    Library& operator=(Library&& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        Other.Storage = nullptr;
    }



    inline Registration CreateRegistration() const noexcept;

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

    DataStore* Storage {nullptr};
    friend class Base<Library>;
};

class Settings : public QUIC_SETTINGS {
    Settings() noexcept { IsSetFlags = 0; }
    Settings& SetSendBufferingEnabled(bool Value) noexcept { SendBufferingEnabled = Value; IsSet.SendBufferingEnabled = TRUE; return *this; }
    Settings& SetPacingEnabled(bool Value) noexcept { PacingEnabled = Value; IsSet.PacingEnabled = TRUE; return *this; }
    Settings& SetMigrationEnabled(bool Value) noexcept { MigrationEnabled = Value; IsSet.MigrationEnabled = TRUE; return *this; }
    Settings& SetDatagramReceiveEnabled(bool Value) noexcept { DatagramReceiveEnabled = Value; IsSet.DatagramReceiveEnabled = TRUE; return *this; }
    Settings& SetServerResumptionLevel(QUIC_SERVER_RESUMPTION_LEVEL Value) noexcept { ServerResumptionLevel = Value; IsSet.ServerResumptionLevel = TRUE; return *this; }
    Settings& SetIdleTimeoutMs(uint64_t Value) noexcept { IdleTimeoutMs = Value; IsSet.IdleTimeoutMs = TRUE; return *this; }
    Settings& SetHandshakeIdleTimeoutMs(uint64_t Value) noexcept { HandshakeIdleTimeoutMs = Value; IsSet.HandshakeIdleTimeoutMs = TRUE; return *this; }
    Settings& SetDisconnectTimeoutMs(uint32_t Value) noexcept { DisconnectTimeoutMs = Value; IsSet.DisconnectTimeoutMs = TRUE; return *this; }
    Settings& SetPeerBidiStreamCount(uint16_t Value) noexcept { PeerBidiStreamCount = Value; IsSet.PeerBidiStreamCount = TRUE; return *this; }
    Settings& SetPeerUnidiStreamCount(uint16_t Value) noexcept { PeerUnidiStreamCount = Value; IsSet.PeerUnidiStreamCount = TRUE; return *this; }
    Settings& SetMaxBytesPerKey(uint64_t Value) noexcept { MaxBytesPerKey = Value; IsSet.MaxBytesPerKey = TRUE; return *this; }
    Settings& SetMaxAckDelayMs(uint32_t Value) noexcept { MaxAckDelayMs = Value; IsSet.MaxAckDelayMs = TRUE; return *this; }
};

class Alpn {
    QUIC_BUFFER Buffer;
    std::string RawAlpn;
public:
    Alpn(std::string Alpn) noexcept {
        RawAlpn = std::move(Alpn);
        Buffer.Buffer = (uint8_t*)RawAlpn.c_str();
        Buffer.Length = (uint32_t)RawAlpn.length();
    }
    operator const QUIC_BUFFER*() const noexcept { return &Buffer; }
};

class CredentialConfig : public QUIC_CREDENTIAL_CONFIG {
    explicit CredentialConfig(const QUIC_CREDENTIAL_CONFIG& Config) noexcept {
        QUIC_CREDENTIAL_CONFIG* thisStruct = this;
        memcpy(thisStruct, &Config, sizeof(QUIC_CREDENTIAL_CONFIG));
    }

    explicit CredentialConfig(QUIC_CREDENTIAL_FLAGS _Flags = QUIC_CREDENTIAL_FLAG_CLIENT) noexcept {
        QUIC_CREDENTIAL_CONFIG* thisStruct = this;
        memset(thisStruct, 0, sizeof(QUIC_CREDENTIAL_CONFIG));
        Flags = _Flags;
    }
};

class Registration : public Base<Registration> {
private:
    struct DataStore: public Base<Registration>::BaseDataStore {
        DataStore(const Library& Lib) noexcept : Library{Lib} {
            InitStatus = Library;
        }
        HQUIC Registration {nullptr};
        Library Library;
    };
public:
    explicit Registration(const Library& Lib) noexcept : Base{Lib} {
        Storage = new(std::nothrow) DataStore{Lib};
        if (!*this) return;
        Storage->InitStatus = GetTable()->RegistrationOpen(nullptr, &Storage->Registration);
    }

    Registration(const Library& Lib, const std::string& AppName, QUIC_EXECUTION_PROFILE Profile = QUIC_EXECUTION_PROFILE_LOW_LATENCY) noexcept : Base{Lib} {
        Storage = new(std::nothrow) DataStore{Lib};
        if (!*this) return;
        const QUIC_REGISTRATION_CONFIG RegConfig = { AppName.c_str(), Profile};
        Storage->InitStatus = GetTable()->RegistrationOpen(&RegConfig, &Storage->Registration);
    }
    ~Registration() noexcept {
        Close();
    }

    Registration(const Registration& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        AddRef();
    }

    Registration& operator=(const Registration& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        AddRef();
    }

    Registration(Registration&& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    Registration& operator=(Registration&& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    void Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAGS Flags, QUIC_UINT62 ErrorCode) noexcept {
        GetTable()->RegistrationShutdown(Storage->Registration, Flags, ErrorCode);
    }

    operator const Library&() const noexcept {
        return Storage->Library;
    }

    operator HQUIC() const noexcept {
        return Storage->Registration;
    }

    inline Configuration CreateConfiguration(const Alpn& Alpn) const noexcept;
    inline Configuration CreateConfiguration(const Alpn& Alpn, const CredentialConfig& CredConfig) const noexcept;
    inline Configuration CreateConfiguration(const Alpn& Alpn, const Settings& Settings) const noexcept;
    inline Configuration CreateConfiguration(const Alpn& Alpn, const Settings& Settings, const CredentialConfig& CredConfig) const noexcept;

private:
    void Close() {
        if (Release()) {
            if (Storage->Registration) {
                GetTable()->RegistrationClose(Storage->Registration);
            }
            delete Storage;
            Storage = nullptr;
        }
    }

    DataStore* Storage {nullptr};
    friend class Base<Registration>;
};

class Configuration : public Base<Configuration> {
private:
    struct DataStore : public Base<Configuration>::BaseDataStore {
        DataStore(const Registration& Reg) noexcept : Library{Reg} {
            InitStatus = Reg;
        }
        HQUIC Configuration {nullptr};
        Library Library;
    };
public:

    Configuration(const Registration& Reg, const Alpn& Alpn) noexcept : Base{Reg} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        Storage->InitStatus = GetTable()->ConfigurationOpen(Reg, Alpn, 1, nullptr, 0, nullptr, &Storage->Configuration);
    }

    Configuration(const Registration& Reg, const Alpn& Alpn, const CredentialConfig& CredConfig) noexcept : Base{Reg} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        Storage->InitStatus = GetTable()->ConfigurationOpen(Reg, Alpn, 1, nullptr, 0, nullptr, &Storage->Configuration);
        if (!*this) return;
        Storage->InitStatus = LoadCredential(CredConfig);
    }

    Configuration(const Registration& Reg, const Alpn& Alpn, const Settings& Settings) noexcept : Base{Reg} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        Storage->InitStatus = GetTable()->ConfigurationOpen(Reg, Alpn, 1, &Settings, sizeof(Settings), nullptr, &Storage->Configuration);
    }

    Configuration(const Registration& Reg, const Alpn& Alpn, const Settings& Settings, const CredentialConfig& CredConfig) noexcept : Base{Reg} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        Storage->InitStatus = GetTable()->ConfigurationOpen(Reg, Alpn, 1, &Settings, sizeof(Settings), nullptr, &Storage->Configuration);
        if (!*this) return;
        Storage->InitStatus = LoadCredential(CredConfig);
    }

    QUIC_STATUS LoadCredential(const QUIC_CREDENTIAL_CONFIG& CredConfig) noexcept {
        return GetTable()->ConfigurationLoadCredential(*this, &CredConfig);
    }

    // TODO Multiple ALPN Constructors

    ~Configuration() noexcept {
        Close();
    }

    Configuration(const Configuration& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        AddRef();
    }

    Configuration& operator=(const Configuration& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        AddRef();
    }

    Configuration(Configuration&& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    Configuration& operator=(Configuration&& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    operator const Library&() const noexcept {
        return Storage->Library;
    }

    operator HQUIC() const noexcept {
        return Storage->Configuration;
    }

private:
    void Close() noexcept {
        if (Release()) {
            if (Storage->Configuration) {
                GetTable()->ConfigurationClose(Storage->Configuration);
            }
            delete Storage;
            Storage = nullptr;
        }
    }

    DataStore* Storage {nullptr};
    friend class Base<Configuration>;
};

class Listener : public Base<Listener> {
private:
    struct DataStore: public Base<Listener>::BaseDataStore {
        DataStore(const Registration& Reg) noexcept : Library{Reg} {
            InitStatus = Reg;
        }
        HQUIC Listener {nullptr};
        Library Library;
    };
public:

    explicit Listener(const Registration& Reg) noexcept : Base{Reg} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        // Add ref when creating listener
        // Close event will remove a ref.
        // If function fails, remove the added ref.
        Storage->InitStatus = GetTable()->ListenerOpen(Reg, nullptr, nullptr, &Storage->Listener);
    }

    ~Listener() noexcept {
        Close();
    }

    Listener(const Listener& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        AddRef();
    }

    Listener& operator=(const Listener& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        AddRef();
    }

    Listener(Listener&& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    Listener& operator=(Listener&& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    operator const Library&() const noexcept {
        return Storage->Library;
    }

    operator HQUIC() const noexcept {
        return Storage->Listener;
    }

private:
    void Close() {
        if (Release()) {
            if (Storage->Listener) {
                GetTable()->ListenerClose(Storage->Listener);
            }
            delete Storage;
            Storage = nullptr;
        }
    }

    DataStore* Storage {nullptr};
    friend class Base<Listener>;
};

inline Registration Library::CreateRegistration() const noexcept {
    return Registration{*this};
}

inline Configuration Registration::CreateConfiguration(const Alpn& Alpn) const noexcept {
    return Configuration{*this, Alpn};
}

inline Configuration Registration::CreateConfiguration(const Alpn& Alpn, const CredentialConfig& CredConfig) const noexcept {
    return Configuration{*this, Alpn, CredConfig};
}

inline Configuration Registration::CreateConfiguration(const Alpn& Alpn, const Settings& Settings) const noexcept {
    return Configuration{*this, Alpn, Settings};
}

inline Configuration Registration::CreateConfiguration(const Alpn& Alpn, const Settings& Settings, const CredentialConfig& CredConfig) const noexcept {
    return Configuration{*this, Alpn, Settings, CredConfig};
}

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
