// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>
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

void Module::Interface::ScanAPs(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx);
    u32 size = rp.Pop<u32>();
    std::vector<u8> buffer(size, 0x00);

    ctx.RunAsync(
        [](Kernel::HLERequestContext&) -> s64 {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::seconds(1)).count();
        },
        [](Kernel::HLERequestContext&) -> void {}
    ); // simulate a 1-second wait to satisfy Nintendo

    // --- seed RNG from hardware entropy ---
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);

    // AP entry size is 0x34 bytes. Generate between 3 and 6 entries.
    constexpr u32 ENTRY_SIZE = 0x34;
    const u8 num_entries = static_cast<u8>(3 + (rng() % 4)); // 3-6
    const u32 data_size = num_entries * ENTRY_SIZE;

    if (data_size > size) {
        IPC::RequestBuilder rb = rp.MakeBuilder(2, 2);
        rb.Push(ResultSuccess);
        rb.Push<u32>(0);
        rb.PushStaticBuffer(std::move(buffer), 0);
        return;
    }

    // Security type table from acDataDoc.md
    static const u16 kSecTypes[] = {
        0x0000, // No security
        0x0101, // WEP
        0x0202, // WPA-PSK (TKIP)
        0x0303, // WPA-PSK (AES)
        0x0404, // WPA2-PSK (TKIP)
        0x0505, // WPA2-PSK (AES)
    };
    // Standard non-overlapping 2.4GHz channels
    static const u8 kChannels[] = {1, 6, 11};

    // Simple SSID pool — realistic enough to not confuse the game
    static const char* kSSIDs[] = {
        "NETGEAR",  "ASUS",     "Linksys",  "TP-Link",
        "XFINITY",  "Spectrum", "HomeNet",  "ATT-WiFi",
        "Verizon",  "MyWiFi",   "CoxWifi",  "Optimum",
    };

    for (u8 i = 0; i < num_entries; ++i) {
        u8* e = buffer.data() + i * ENTRY_SIZE;
        // All bytes are already 0x00 from buffer initialisation.

        // 0x00 — SSID length (u32 LE)
        const char* ssid_str = kSSIDs[rng() % 12];
        const u32 ssid_len = static_cast<u32>(std::strlen(ssid_str));
        e[0x00] = static_cast<u8>(ssid_len);
        e[0x01] = 0; e[0x02] = 0; e[0x03] = 0;

        // 0x04 — SSID (32 bytes, zero-padded)
        std::memcpy(e + 0x04, ssid_str, ssid_len);

        // 0x24 — MAC address (6 bytes, locally-administered unicast)
        for (int b = 0; b < 6; ++b)
            e[0x24 + b] = static_cast<u8>(dist(rng));
        e[0x24] = (e[0x24] & 0xFE) | 0x02; // locally administered, unicast

        // 0x2A — padding (already 0x00)

        // 0x2C — signal strength (s16 LE), range 1-80
        const s16 signal = static_cast<s16>(1 + (rng() % 80));
        e[0x2C] = static_cast<u8>(signal & 0xFF);
        e[0x2D] = static_cast<u8>((signal >> 8) & 0xFF);

        // 0x2E — signal strength summary (0-3)
        if      (signal >= 60) e[0x2E] = 3;
        else if (signal >= 30) e[0x2E] = 2;
        else if (signal >= 15) e[0x2E] = 1;
        else                   e[0x2E] = 0;

        // 0x2F — channel
        e[0x2F] = kChannels[rng() % 3];

        // 0x30 — security type (u16 LE)
        const u16 sec = kSecTypes[rng() % 6];
        e[0x30] = static_cast<u8>(sec & 0xFF);
        e[0x31] = static_cast<u8>((sec >> 8) & 0xFF);

        // 0x32 — padding (already 0x00)
    }

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 2);
    rb.Push(ResultSuccess);
    rb.Push<u32>(num_entries);
    rb.PushStaticBuffer(std::move(buffer), 0);

    LOG_DEBUG(Service_AC, "ScanAPs returning {} randomized entries", num_entries);
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
