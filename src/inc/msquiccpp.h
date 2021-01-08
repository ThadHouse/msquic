#pragma once

#include "msquic.h"

#define CUSTOM_FUNCTIONS

#ifdef CUSTOM_FUNCTIONS
#include "msquiccpp_kernel.h"
#else
#include <atomic>
#include <functional>
#include <type_traits>
#endif

#include <string>
//#include <atomic>
//#include <string>
//#include <functional>



namespace ms::quic {
class Registration;
class Connection;
class Stream;
class Library;
class Listener;
class Configuration;
class Connection;

#ifdef CUSTOM_FUNCTIONS
using quic_atomic_int = stdkm::atomic_int;
using quic_string = std::string;

template<class T>
constexpr stdkm::remove_reference_t<T>&& quic_move(T&& t) noexcept {
    return static_cast<typename stdkm::remove_reference<T>::type&&>(t);
}

template<typename T>
using quic_function = stdkm::function<T>;
#else
using quic_atomic_int = std::atomic_int;
using quic_string = std::string;

template<class T>
constexpr std::remove_reference_t<T>&& quic_move(T&& t) noexcept {
    return static_cast<typename std::remove_reference<T>::type&&>(t);
}

template<typename T>
using quic_function = std::function<T>;
#endif


class ApiTableBase {
public:
    constexpr const QUIC_API_TABLE* GetApiTable() const noexcept {
        return ApiTable;
    }
protected:
    const QUIC_API_TABLE* ApiTable {nullptr};

    explicit ApiTableBase(const QUIC_API_TABLE* Table) noexcept : ApiTable{Table} {
    }

    ApiTableBase(const ApiTableBase& Other) noexcept {
        ApiTable = Other.ApiTable;
    }

    ApiTableBase(ApiTableBase&& Other) noexcept {
        ApiTable = Other.ApiTable;
    }

    ApiTableBase& operator=(const ApiTableBase& Other) noexcept {
        ApiTable = Other.ApiTable;
    }

    ApiTableBase& operator=(ApiTableBase&& Other) noexcept {
        ApiTable = Other.ApiTable;
    }
};

template <class T>
class Base : public ApiTableBase {
private:
protected:
    struct BaseDataStore {
        quic_atomic_int RefCount{1};
        QUIC_STATUS InitStatus{ QUIC_STATUS_SUCCESS };
        quic_function<void()> DeletedFunc;
    };

    explicit Base(const QUIC_API_TABLE* Table) noexcept : ApiTableBase{Table} {
    }

    Base(const Base& Other) noexcept : ApiTableBase{Other} {
    }

    Base(Base&& Other) noexcept : ApiTableBase{Other} {
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

    T& OnDeleted(quic_function<void()> Deleter) noexcept {
        static_cast<T*>(this)->Storage->DeletedFunc = quic_move(Deleter);
        return *static_cast<T*>(this);
    }

    const T& OnDeleted(quic_function<void()> Deleter) const noexcept {
        static_cast<const T*>(this)->Storage->DeletedFunc = quic_move(Deleter);
        return *static_cast<const T*>(this);
    }
protected:
    void AddRef() noexcept {
        static_cast<T*>(this)->Storage->RefCount.fetch_add(1);
    }
    bool Release() noexcept {
        if (static_cast<T*>(this)->Storage) {
            return static_cast<T*>(this)->Storage->RefCount.fetch_sub(1) == 1;
        }
        // Return false if already deleted
        return false;
    }
    void CallDeleter() noexcept {
        auto Deleter = quic_move(static_cast<T*>(this)->Storage->DeletedFunc);
        if (Deleter) {
            Deleter();
        }
    }
};

class Library : public ApiTableBase {
public:
    Library() noexcept : ApiTableBase{nullptr} {
        InitStatus = MsQuicOpen(&ApiTable);
    }
    ~Library() noexcept {
        if (ApiTable) {
            MsQuicClose(ApiTable);
        }
    }

    Library(const Library&) = delete;
    Library(Library&& Other) = delete;
    Library& operator=(const Library&) = delete;
    Library& operator=(Library&&) = delete;

    constexpr operator QUIC_STATUS() const noexcept {
        return InitStatus;
    }

    constexpr operator bool() const noexcept {
        return QUIC_SUCCEEDED(this->operator QUIC_STATUS());
    }

    inline Registration CreateRegistration() const noexcept;
private:

    const QUIC_API_TABLE* ApiTable {nullptr};
    QUIC_STATUS InitStatus{QUIC_STATUS_SUCCESS};
};

class Settings : public QUIC_SETTINGS {
public:
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
    quic_string RawAlpn;
public:
    Alpn(quic_string Alpn) noexcept {
        RawAlpn = quic_move(Alpn);
        Buffer.Buffer = (uint8_t*)RawAlpn.c_str();
        Buffer.Length = (uint32_t)RawAlpn.length();
    }
    operator const QUIC_BUFFER*() const noexcept { return &Buffer; }
};

class CredentialConfig : public QUIC_CREDENTIAL_CONFIG {
public:
    CredentialConfig(const QUIC_CREDENTIAL_CONFIG& Config) noexcept {
        QUIC_CREDENTIAL_CONFIG* thisStruct = this;
        memcpy(thisStruct, &Config, sizeof(QUIC_CREDENTIAL_CONFIG));
    }

    CredentialConfig(QUIC_CREDENTIAL_FLAGS _Flags = QUIC_CREDENTIAL_FLAG_CLIENT) noexcept {
        QUIC_CREDENTIAL_CONFIG* thisStruct = this;
        memset(thisStruct, 0, sizeof(QUIC_CREDENTIAL_CONFIG));
        Flags = _Flags;
    }
};

class Registration : public ApiTableBase {
public:
    explicit Registration(const Library& Lib) noexcept : ApiTableBase{Lib.GetApiTable()} {
        InitStatus = GetApiTable()->RegistrationOpen(nullptr, &HRegistration);
    }

    Registration(const Library& Lib, const std::string& AppName, QUIC_EXECUTION_PROFILE Profile = QUIC_EXECUTION_PROFILE_LOW_LATENCY) noexcept : ApiTableBase{Lib.GetApiTable()} {
        const QUIC_REGISTRATION_CONFIG RegConfig = { AppName.c_str(), Profile};
        InitStatus = GetApiTable()->RegistrationOpen(&RegConfig, &HRegistration);
    }

    ~Registration() noexcept {
        if (CloseAllConns && this->HRegistration) {
            Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 1);
        }
        if (HRegistration) {
            GetApiTable()->RegistrationClose(HRegistration);
        }
    }

    Registration(const Registration&) = delete;
    Registration(Registration&& Other) = delete;
    Registration& operator=(const Registration&) = delete;
    Registration& operator=(Registration&&) = delete;

    constexpr operator QUIC_STATUS() const noexcept {
        return InitStatus;
    }

    constexpr operator bool() const noexcept {
        return QUIC_SUCCEEDED(this->operator QUIC_STATUS());
    }

    void Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAGS Flags, QUIC_UINT62 ErrorCode) noexcept {
        GetApiTable()->RegistrationShutdown(HRegistration, Flags, ErrorCode);
    }

    operator HQUIC() const noexcept {
        return HRegistration;
    }

    Registration& CloseAllConnectionsOnDelete() noexcept {
        CloseAllConns = true;
        return *this;
    }

    inline Configuration CreateConfiguration(const Alpn& Alpn) const noexcept;
    inline Configuration CreateConfiguration(const Alpn& Alpn, const CredentialConfig& CredConfig) const noexcept;
    inline Configuration CreateConfiguration(const Alpn& Alpn, const Settings& Settings) const noexcept;
    inline Configuration CreateConfiguration(const Alpn& Alpn, const Settings& Settings, const CredentialConfig& CredConfig) const noexcept;
    inline Listener CreateListener() const noexcept;

private:
    QUIC_STATUS InitStatus;
    HQUIC HRegistration{nullptr};
    const QUIC_API_TABLE* ApiTable{nullptr};
    bool CloseAllConns{false};
};

class Configuration : public Base<Configuration> {
private:
    struct DataStore : public Base<Configuration>::BaseDataStore {
        DataStore(const Registration& Reg) noexcept {
            InitStatus = Reg;
        }
        HQUIC Configuration {nullptr};
    };
public:

    Configuration(const Registration& Reg, const Alpn& Alpn) noexcept : Base{Reg.GetApiTable()} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        Storage->InitStatus = GetApiTable()->ConfigurationOpen(Reg, Alpn, 1, nullptr, 0, nullptr, &Storage->Configuration);
    }

    Configuration(const Registration& Reg, const Alpn& Alpn, const CredentialConfig& CredConfig) noexcept : Base{Reg.GetApiTable()} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        Storage->InitStatus = GetApiTable()->ConfigurationOpen(Reg, Alpn, 1, nullptr, 0, nullptr, &Storage->Configuration);
        if (!*this) return;
        Storage->InitStatus = LoadCredential(CredConfig);
    }

    Configuration(const Registration& Reg, const Alpn& Alpn, const Settings& Settings) noexcept : Base{Reg.GetApiTable()} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        Storage->InitStatus = GetApiTable()->ConfigurationOpen(Reg, Alpn, 1, &Settings, sizeof(Settings), nullptr, &Storage->Configuration);
    }

    Configuration(const Registration& Reg, const Alpn& Alpn, const Settings& Settings, const CredentialConfig& CredConfig) noexcept : Base{Reg.GetApiTable()} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        Storage->InitStatus = GetApiTable()->ConfigurationOpen(Reg, Alpn, 1, &Settings, sizeof(Settings), nullptr, &Storage->Configuration);
        if (!*this) return;
        Storage->InitStatus = LoadCredential(CredConfig);
    }

    QUIC_STATUS LoadCredential(const QUIC_CREDENTIAL_CONFIG& CredConfig) noexcept {
        return GetApiTable()->ConfigurationLoadCredential(*this, &CredConfig);
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

    operator HQUIC() const noexcept {
        return Storage->Configuration;
    }

private:
    void Close() noexcept {
        if (Release()) {
            if (Storage->Configuration) {
                GetApiTable()->ConfigurationClose(Storage->Configuration);
            }
            CallDeleter();
            delete Storage;
            Storage = nullptr;
        }
    }

    DataStore* Storage {nullptr};
    friend class Base<Configuration>;
};

class Connection : public Base<Connection> {
private:
    struct DataStore : public Base<Connection>::BaseDataStore {
        DataStore(const Registration& Reg) noexcept {
            InitStatus = Reg;
            ApiTable = Reg.GetApiTable();
        }
        DataStore(const QUIC_API_TABLE* Table) noexcept {
            InitStatus = QUIC_STATUS_SUCCESS;
            ApiTable = Table;
        }
        HQUIC Connection {nullptr};
        std::function<QUIC_STATUS(ms::quic::Connection&, QUIC_CONNECTION_EVENT*)> ConnectionCallback;
        const QUIC_API_TABLE* ApiTable;
    };
    Connection(DataStore* Store) noexcept : Base{Store->ApiTable} {
        this->Storage = Store;
    }
    QUIC_CONNECTION_CALLBACK_HANDLER ConnCallbackFunc() noexcept {
        return [](HQUIC Handle, void* Context, QUIC_CONNECTION_EVENT* Event) noexcept -> QUIC_STATUS {
                                DataStore* Storage = static_cast<DataStore*>(Context);
                                QUIC_STATUS RetVal = QUIC_STATUS_SUCCESS;
                                Connection Conn{Storage};
                                if (Storage->ConnectionCallback) {
                                    RetVal = Storage->ConnectionCallback(Conn, Event);
                                }

                                if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
                                    Conn.SetConnectionFunc(nullptr);
                                    Conn.Close();
                                } else {
                                    Conn.Storage = nullptr;
                                }

                                UNREFERENCED_PARAMETER(Handle);
                                return RetVal;
                            };
    }
    Connection(HQUIC Handle, const QUIC_API_TABLE* ApiTable) noexcept : Base{ApiTable} {
        Storage = new(std::nothrow) DataStore{ApiTable};
        if (!*this) return;
        Storage->Connection = Handle;
        AddRef();
        GetApiTable()->SetCallbackHandler(Handle, (void*)ConnCallbackFunc(), Storage);
        Storage->InitStatus = QUIC_STATUS_SUCCESS;
    }
    friend class Listener;
public:
    explicit Connection(const Registration& Reg) noexcept : Base{Reg.GetApiTable()} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;
        // Add ref to keep alive in callback
        AddRef();
        Storage->InitStatus = GetApiTable()->ConnectionOpen(Reg,
        ConnCallbackFunc(), Storage, &Storage->Connection);
        if (FAILED(Storage->InitStatus)) {
            Release();
        }
    }
    ~Connection() noexcept {
        Close();
    }

    Connection(const Connection& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        AddRef();
    }

    Connection& operator=(const Connection& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        AddRef();
    }

    Connection(Connection&& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    Connection& operator=(Connection&& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    operator HQUIC() const noexcept {
        return Storage->Connection;
    }

    QUIC_STATUS Start(const Configuration& Config, QUIC_ADDRESS_FAMILY Af, const quic_string& ServerName, uint16_t ServerPort) noexcept {
        return GetApiTable()->ConnectionStart(*this, Config, Af, ServerName.c_str(), ServerPort);
    }

    QUIC_STATUS SetConfiguration(const Configuration& Config) noexcept {
        return GetApiTable()->ConnectionSetConfiguration(*this, Config);
    }

    QUIC_STATUS SendResumptionTicket(QUIC_SEND_RESUMPTION_FLAGS Flags, const uint8_t* ResumptionData, uint16_t DataLength) const noexcept {
        return GetApiTable()->ConnectionSendResumptionTicket(*this, Flags, DataLength, ResumptionData);
    }

    inline Stream GetPeerStream(QUIC_CONNECTION_EVENT* Event) const noexcept;

    // TODO Make this required on server side.
    Connection& SetConnectionFunc(quic_function<QUIC_STATUS(ms::quic::Connection&, QUIC_CONNECTION_EVENT*)> Func) noexcept {
        Storage->ConnectionCallback = quic_move(Func);
        return *this;
    }

private:
    void Close() {
        if (Release()) {
            if (Storage->Connection) {
                GetApiTable()->ConnectionClose(Storage->Connection);
            }
            CallDeleter();
            delete Storage;
            Storage = nullptr;
        }
    }
    DataStore* Storage {nullptr};
    friend class Base<Connection>;
};

class Stream : public Base<Stream> {
private:
    struct DataStore : public Base<Stream>::BaseDataStore {
        DataStore(const Connection& Conn) noexcept : Connection{Conn} {
            InitStatus = Conn;
        }
        HQUIC Stream {nullptr};
        quic_function<QUIC_STATUS(ms::quic::Stream&, QUIC_STREAM_EVENT*)> StreamCallback;
        Connection Connection;
    };

    explicit Stream(DataStore* Store) noexcept : Base{Store->Connection.GetApiTable()}, Storage{Store} {
    }

    QUIC_STREAM_CALLBACK_HANDLER StreamCallbackFunc() noexcept {
        return [](HQUIC Handle, void* Context, QUIC_STREAM_EVENT* Event) noexcept -> QUIC_STATUS {
            DataStore* Storage = static_cast<DataStore*>(Context);
            QUIC_STATUS RetVal = QUIC_STATUS_SUCCESS;
            Stream Strm{Storage};
            if (Storage->StreamCallback) {
                RetVal = Storage->StreamCallback(Strm, Event);
            }

            if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
                Strm.SetStreamFunc(nullptr);
                Strm.Close();
            } else {
                Strm.Storage = nullptr;
            }

            UNREFERENCED_PARAMETER(Handle);
            return RetVal;
        };
    }

    Stream(HQUIC Handle, const Connection& Conn) noexcept: Base{Conn.GetApiTable()} {
        Storage = new(std::nothrow)DataStore{Conn};
        if (!*this) return;
        Storage->Stream = Handle;
        AddRef();
        Storage->InitStatus = QUIC_STATUS_SUCCESS;
        GetApiTable()->SetCallbackHandler(Handle, (void*)StreamCallbackFunc(), Storage);
    }
public:
    explicit Stream(const Connection& Conn, QUIC_STREAM_OPEN_FLAGS Flags = QUIC_STREAM_OPEN_FLAG_NONE) noexcept : Base{Conn.GetApiTable()} {
        Storage = new(std::nothrow)DataStore{Conn};
        if (!*this) return;
        // Add ref to keep alive in callback
        AddRef();
        Storage->InitStatus = GetApiTable()->StreamOpen(Conn, Flags, StreamCallbackFunc(), Storage, &Storage->Stream);
        if (FAILED(Storage->InitStatus)) {
            Release();
        }
    }

    ~Stream() noexcept {
        Close();
    }

    Stream(const Stream& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        AddRef();
    }

    Stream& operator=(const Stream& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        AddRef();
    }

    Stream(Stream&& Other) noexcept : Base{Other} {
        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    Stream& operator=(Stream&& Other) noexcept {
        Close();
        Base::operator=(Other);

        Storage = Other.Storage;
        Other.Storage = nullptr;
    }

    operator HQUIC() const noexcept {
        return Storage->Stream;
    }

    Stream& SetStreamFunc(quic_function<QUIC_STATUS(ms::quic::Stream&, QUIC_STREAM_EVENT*)> Func) noexcept {
        Storage->StreamCallback = quic_move(Func);
        return *this;
    }

    QUIC_STATUS Shutdown(QUIC_STREAM_SHUTDOWN_FLAGS Flags, QUIC_UINT62 ErrorCode) const noexcept {
        return GetApiTable()->StreamShutdown(*this, Flags, ErrorCode);
    }

    QUIC_STATUS Send(const QUIC_BUFFER* const Buffers, uint32_t BufferCount, QUIC_SEND_FLAGS Flags, void* ClientSendContext) const noexcept {
        return GetApiTable()->StreamSend(*this, Buffers, BufferCount, Flags, ClientSendContext);
    }

private:
    void Close() {
        if (Release()) {
            if (Storage->Stream) {
                GetApiTable()->StreamClose(Storage->Stream);
            }
            CallDeleter();
            delete Storage;
            Storage = nullptr;
        }
    }
    DataStore* Storage{nullptr};
    friend class Base<Stream>;
    friend class Connection;
};

class Listener : public Base<Listener> {
private:
    struct DataStore: public Base<Listener>::BaseDataStore {
        DataStore(const Registration& Reg) noexcept {
            InitStatus = Reg;
            ApiTable = Reg.GetApiTable();
        }
        HQUIC Listener {nullptr};
        std::function<QUIC_STATUS(ms::quic::Listener&, QUIC_LISTENER_EVENT*)> ListenerCallback;
        const QUIC_API_TABLE* ApiTable;
    };

    explicit Listener(DataStore* Store) noexcept : Base{Store->ApiTable}, Storage{Store} {
    }
public:

    explicit Listener(const Registration& Reg) noexcept : Base{Reg.GetApiTable()} {
        Storage = new(std::nothrow) DataStore{Reg};
        if (!*this) return;

        Storage->InitStatus = GetApiTable()->ListenerOpen(Reg,
            [](HQUIC Handle, void* Context, QUIC_LISTENER_EVENT* Event) -> QUIC_STATUS {
                DataStore* Storage = static_cast<DataStore*>(Context);
                Listener Listener{Storage};
                if (Storage->ListenerCallback) {
                    QUIC_STATUS RetVal = Storage->ListenerCallback(Listener, Event);
                    Listener.Storage = nullptr;
                    return RetVal;
                }
                UNREFERENCED_PARAMETER(Handle);
                return QUIC_STATUS_USER_CANCELED;
            }
        , Storage, &Storage->Listener);
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

    operator HQUIC() const noexcept {
        return Storage->Listener;
    }

    Connection GetNewConnection(QUIC_LISTENER_EVENT* Event) const noexcept {
        return Connection{Event->NEW_CONNECTION.Connection, Storage->ApiTable};
    }

    Listener& SetListenerFunc(quic_function<QUIC_STATUS(ms::quic::Listener&, QUIC_LISTENER_EVENT*)> Func) noexcept {
        Storage->ListenerCallback = quic_move(Func);
        return *this;
    }

    QUIC_STATUS Start(const Alpn& Alpn, uint16_t UdpPort) const noexcept {
        QUIC_ADDR Address;
        memset(&Address, 0, sizeof(Address));
        QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
        QuicAddrSetPort(&Address, UdpPort);
        return GetApiTable()->ListenerStart(*this, Alpn, 1, &Address);
    }

    void Stop() const noexcept {
        GetApiTable()->ListenerStop(*this);
    }

    Listener& StopOnCleanup() noexcept {
        StopCleanup = true;
        return *this;
    }

private:
    void Close() noexcept {
        if (StopCleanup && Storage->Listener) {
            GetApiTable()->ListenerStop(Storage->Listener);
            SetListenerFunc(nullptr);
        }
        if (Release()) {
            if (Storage->Listener) {
                GetApiTable()->ListenerClose(Storage->Listener);
            }
            CallDeleter();
            delete Storage;
            Storage = nullptr;
        }
    }

    DataStore* Storage {nullptr};
    bool StopCleanup{false};
    friend class Base<Listener>;
};

inline Stream Connection::GetPeerStream(QUIC_CONNECTION_EVENT* Event) const noexcept {
    return Stream{Event->PEER_STREAM_STARTED.Stream, *this};
}

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

inline Listener Registration::CreateListener() const noexcept {
    return Listener{*this};
}
}
