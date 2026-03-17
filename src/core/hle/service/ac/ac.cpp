// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>
#include <vector>
#include "common/archives.h"
#include "common/common_types.h"
#include "common/logging/log.h"
#include "common/settings.h"
#include "core/core.h"
#include "core/hle/ipc.h"
#include "core/hle/ipc_helpers.h"
#include "core/hle/kernel/event.h"
#include "core/hle/kernel/handle_table.h"
#include "core/hle/kernel/resource_limit.h"
#include "core/hle/kernel/shared_page.h"
#include "core/hle/result.h"
#include "core/hle/service/ac/ac.h"
#include "core/hle/service/ac/ac_i.h"
#include "core/hle/service/ac/ac_u.h"
#include "core/hle/service/soc/soc_u.h"
#include "core/memory.h"

SERIALIZE_EXPORT_IMPL(Service::AC::Module)
SERVICE_CONSTRUCT_IMPL(Service::AC::Module)

namespace Service::AC {
void Module::Interface::CreateDefaultConfig(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    std::vector<u8> buffer(sizeof(ACConfig));
    std::memcpy(buffer.data(), &ac->default_config, buffer.size());

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(ResultSuccess);
    rb.PushStaticBuffer(std::move(buffer), 0);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::ConnectAsync(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    rp.Skip(2, false); // ProcessId descriptor
    ac->connect_event = rp.PopObject<Kernel::Event>();
    rp.Skip(2, false); // Buffer descriptor

    if (ac->connect_event) {
        ac->connect_event->SetName("AC:connect_event");
        ac->connect_event->Signal();
        ac->ac_connected = true;
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::GetConnectResult(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    rp.Skip(2, false); // ProcessId descriptor

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::CancelConnectAsync(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    rp.Skip(2, false); // ProcessId descriptor

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ac->ac_connected ? Result(static_cast<ErrorDescription>(301), ErrorModule::AC,
                                      ErrorSummary::InvalidState, ErrorLevel::Usage)
                             : Result(static_cast<ErrorDescription>(302), ErrorModule::AC,
                                      ErrorSummary::InvalidState, ErrorLevel::Usage));

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::CloseAsync(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    rp.Skip(2, false); // ProcessId descriptor

    ac->close_event = rp.PopObject<Kernel::Event>();

    if (ac->ac_connected && ac->disconnect_event) {
        ac->disconnect_event->Signal();
    }

    if (ac->close_event) {
        ac->close_event->SetName("AC:close_event");
        ac->close_event->Signal();
    }

    ac->ac_connected = false;

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);
}

void Module::Interface::GetCloseResult(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    rp.Skip(2, false); // ProcessId descriptor

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::GetStatus(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(ResultSuccess);
    rb.Push<u32>(static_cast<u32>(Status::STATUS_INTERNET));
}

void Module::Interface::GetWifiStatus(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(ResultSuccess);
    rb.Push<u32>(static_cast<u32>(WifiStatus::STATUS_CONNECTED_SLOT1));
}

// ---------------------------------------------------------------------------
// AP entry layout (each entry is 0x34 bytes):
//   0x00  u32     SSID length
//   0x04  u8[32]  SSID (UTF-8, zero-padded to fill field)
//   0x24  u8[6]   MAC address
//   0x2A  u8[2]   padding (0x00)
//   0x2C  s16     signal strength
//   0x2E  u8      signal strength summary (0-3)
//   0x2F  u8      channel
//   0x30  u16     security type
//   0x32  u8[2]   padding (0x00)
// ---------------------------------------------------------------------------
static std::pair<u8, std::vector<u8>> GenerateRandomAPs() {
    // Seed a Mersenne Twister from a real entropy source so every call
    // produces a different set of networks.
    std::mt19937 rng{std::random_device{}()};

    auto rand_u8  = [&](u8  lo, u8  hi) -> u8  { return static_cast<u8> (std::uniform_int_distribution<int>(lo, hi)(rng)); };
    auto rand_u16 = [&](u16 lo, u16 hi) -> u16 { return static_cast<u16>(std::uniform_int_distribution<int>(lo, hi)(rng)); };
    auto rand_s16 = [&](s16 lo, s16 hi) -> s16 { return static_cast<s16>(std::uniform_int_distribution<int>(lo, hi)(rng)); };

    // Plausible SSID prefixes; a random 4-hex-digit suffix is appended.
    static const std::vector<std::string> kSSIDPrefixes = {
        "NETGEAR-", "ASUS_",    "Linksys",   "TP-Link_", "XFINITY",
        "Spectrum", "ATT-WiFi", "Verizon-",  "HomeNet",  "MyWiFi-",
        "CoxWifi",  "Optimum",  "BELL_",     "BT-Hub",   "SKY_WiFi",
    };

    // Security type values as specified in acDataDoc.md
    static const std::array<u16, 6> kSecTypes = {
        0x0000, // No security
        0x0101, // WEP
        0x0202, // WPA-PSK  (TKIP)
        0x0303, // WPA-PSK  (AES)
        0x0404, // WPA2-PSK (TKIP)
        0x0505, // WPA2-PSK (AES)
    };

    // Realistic non-overlapping 2.4 GHz channel choices
    static const std::array<u8, 3> kChannels = {1, 6, 11};

    constexpr std::size_t ENTRY_SIZE  = 0x34;
    constexpr std::size_t SSID_FIELD  = 32; // fixed field width in the struct

    const u8 num_entries = rand_u8(3, 8);
    std::vector<u8> buffer(num_entries * ENTRY_SIZE, 0x00);

    for (u8 i = 0; i < num_entries; ++i) {
        u8* e = buffer.data() + i * ENTRY_SIZE;

        // --- SSID (0x00 + 0x04) -------------------------------------------
        // Pick a prefix and append a random 4-hex-digit suffix.
        std::string prefix = kSSIDPrefixes[rand_u8(0, static_cast<u8>(kSSIDPrefixes.size() - 1))];
        std::ostringstream oss;
        oss << prefix
            << std::hex << std::uppercase
            << std::setw(4) << std::setfill('0') << rand_u16(0, 0xFFFF);
        std::string ssid = oss.str().substr(0, SSID_FIELD); // cap at 32 bytes

        const u32 ssid_len = static_cast<u32>(ssid.size());
        std::memcpy(e + 0x00, &ssid_len, sizeof(ssid_len));
        std::memcpy(e + 0x04, ssid.data(), ssid_len);
        // remaining SSID bytes already 0x00 from vector initialisation

        // --- MAC address (0x24) -------------------------------------------
        // Locally-administered unicast: bit 1 of byte 0 set, bit 0 cleared.
        for (int b = 0; b < 6; ++b)
            e[0x24 + b] = rand_u8(0x00, 0xFF);
        e[0x24] = (e[0x24] & 0xFE) | 0x02;

        // --- Signal strength (0x2C) + summary (0x2E) ----------------------
        const s16 signal = rand_s16(1, 80);
        std::memcpy(e + 0x2C, &signal, sizeof(signal));

        u8 summary;
        if      (signal >= 60) summary = 3;
        else if (signal >= 30) summary = 2;
        else if (signal >= 15) summary = 1;
        else                   summary = 0;
        e[0x2E] = summary;

        // --- Channel (0x2F) -----------------------------------------------
        e[0x2F] = kChannels[rand_u8(0, static_cast<u8>(kChannels.size() - 1))];

        // --- Security type (0x30) -----------------------------------------
        const u16 sec = kSecTypes[rand_u8(0, static_cast<u8>(kSecTypes.size() - 1))];
        std::memcpy(e + 0x30, &sec, sizeof(sec));
        // bytes 0x32-0x33 remain 0x00 (padding)
    }

    return {num_entries, std::move(buffer)};
}

void Module::Interface::ScanAPs(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    const u32 max_size = rp.Pop<u32>();

    // Both the data generation and the IPC reply MUST live inside the
    // completion callback — RunAsync is asynchronous and the context is
    // not ready for a response until the second lambda fires.
    ctx.RunAsync(
        [](Kernel::HLERequestContext&) -> s64 {
            // Simulate a 1-second scan delay to satisfy Nintendo.
            return std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::seconds(1)).count();
        },
        [max_size](Kernel::HLERequestContext& ctx) -> void {
            auto [num_entries, buffer] = GenerateRandomAPs();

            // Clamp to what the caller actually allocated.
            const u32 used = std::min(static_cast<u32>(buffer.size()), max_size);
            buffer.resize(used);
            const u8 clamped_entries = static_cast<u8>(used / 0x34);

            IPC::RequestBuilder rb(ctx, 0x001D, 2, 2);
            rb.Push(ResultSuccess);
            rb.Push<u32>(clamped_entries);
            rb.PushStaticBuffer(std::move(buffer), 0);
        }
    );
}

void Module::Interface::GetInfraPriority(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    [[maybe_unused]] const std::vector<u8>& ac_config = rp.PopStaticBuffer();

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(ResultSuccess);
    rb.Push<u32>(0); // Infra Priority, default 0

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::SetRequestEulaVersion(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    u32 major = rp.Pop<u8>();
    u32 minor = rp.Pop<u8>();

    const std::vector<u8>& ac_config = rp.PopStaticBuffer();

    // TODO(Subv): Copy over the input ACConfig to the stored ACConfig.

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(ResultSuccess);
    rb.PushStaticBuffer(std::move(ac_config), 0);

    LOG_WARNING(Service_AC, "(STUBBED) called, major={}, minor={}", major, minor);
}

void Module::Interface::GetNZoneBeaconNotFoundEvent(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    rp.Skip(2, false); // ProcessId descriptor

    ac->nintendo_zone_beacon_not_found_event = rp.PopObject<Kernel::Event>();

    ac->nintendo_zone_beacon_not_found_event->Signal();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::RegisterDisconnectEvent(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    rp.Skip(2, false); // ProcessId descriptor

    ac->disconnect_event = rp.PopObject<Kernel::Event>();
    if (ac->disconnect_event) {
        ac->disconnect_event->SetName("AC:disconnect_event");
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::GetConnectingProxyEnable(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    constexpr bool proxy_enabled = false;

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(ResultSuccess);
    rb.Push(proxy_enabled);

    LOG_WARNING(Service_AC, "(STUBBED) called");
}

void Module::Interface::IsConnected(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    u32 unk = rp.Pop<u32>();
    u32 unk_descriptor = rp.Pop<u32>();
    u32 unk_param = rp.Pop<u32>();

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(ResultSuccess);
    rb.Push(ac->ac_connected);

    LOG_DEBUG(Service_AC, "(STUBBED) called unk=0x{:08X} descriptor=0x{:08X} param=0x{:08X}", unk,
              unk_descriptor, unk_param);
}

void Module::Interface::SetClientVersion(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);

    u32 version = rp.Pop<u32>();
    rp.Skip(2, false); // ProcessId descriptor

    LOG_WARNING(Service_AC, "(STUBBED) called, version: 0x{:08X}", version);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(ResultSuccess);
}

Module::Interface::Interface(std::shared_ptr<Module> ac, const char* name, u32 max_session)
    : ServiceFramework(name, max_session), ac(std::move(ac)) {}

void InstallInterfaces(Core::System& system) {
    auto& service_manager = system.ServiceManager();
    auto ac = std::make_shared<Module>(system);
    std::make_shared<AC_I>(ac)->InstallAsService(service_manager);
    std::make_shared<AC_U>(ac)->InstallAsService(service_manager);
}

Module::Module(Core::System& system_) : system(system_) {}

template <class Archive>
void Module::serialize(Archive& ar, const unsigned int) {
    DEBUG_SERIALIZATION_POINT;
    ar & ac_connected;
    ar & close_event;
    ar & connect_event;
    ar & disconnect_event;
    ar & nintendo_zone_beacon_not_found_event;
    // default_config is never written to
}
SERIALIZE_IMPL(Module)

} // namespace Service::AC
