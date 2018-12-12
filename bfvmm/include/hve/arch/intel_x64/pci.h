//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef PCI_INTEL_X64_H
#define PCI_INTEL_X64_H

#include <bfdebug.h>
#include <bfbitmanip.h>
#include <arch/x64/portio.h>
#include <bfvmm/hve/arch/intel_x64/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

#include "vmexit/io_instruction.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace intel_x64::pci::iocfg
{

using namespace ::x64::portio;
using addr_t = uint32_t;

namespace off
{
    constexpr const auto mask = 0x00000003UL;
    constexpr const auto from = 0;
    constexpr const auto name = "off";

    inline auto get(addr_t addr) noexcept
    { return get_bits(addr, mask) >> from; }

    inline void set(addr_t &addr, addr_t off) noexcept
    { addr = set_bits(addr, mask, off << from); }

    inline void dump(int level, addr_t val, std::string *msg = nullptr)
    { bfdebug_subnhex(level, name, get(val), msg); }
}

namespace reg
{
    constexpr const auto mask = 0x000000FCUL;
    constexpr const auto from = 2;
    constexpr const auto name = "reg";

    inline auto get(addr_t addr) noexcept
    { return get_bits(addr, mask) >> from; }

    inline void set(addr_t &addr, addr_t reg) noexcept
    { addr = set_bits(addr, mask, reg << from); }

    inline void dump(int level, addr_t val, std::string *msg = nullptr)
    { bfdebug_subnhex(level, name, get(val), msg); }
}

namespace fun
{
    constexpr const auto mask = 0x00000700UL;
    constexpr const auto from = 8;
    constexpr const auto name = "fun";

    inline auto get(addr_t addr) noexcept
    { return get_bits(addr, mask) >> from; }

    inline void set(addr_t &addr, addr_t fun) noexcept
    { addr = set_bits(addr, mask, fun << from); }

    inline void dump(int level, addr_t val, std::string *msg = nullptr)
    { bfdebug_subnhex(level, name, get(val), msg); }
}

namespace dev
{
    constexpr const auto mask = 0x0000F800UL;
    constexpr const auto from = 11;
    constexpr const auto name = "dev";

    inline auto get(addr_t addr) noexcept
    { return get_bits(addr, mask) >> from; }

    inline void set(addr_t &addr, addr_t dev) noexcept
    { addr = set_bits(addr, mask, dev << from); }

    inline void dump(int level, addr_t val, std::string *msg = nullptr)
    { bfdebug_subnhex(level, name, get(val), msg); }
}

namespace bus
{
    constexpr const auto mask = 0x00FF0000UL;
    constexpr const auto from = 16;
    constexpr const auto name = "bus";

    inline auto get(addr_t addr) noexcept
    { return get_bits(addr, mask) >> from; }

    inline void set(addr_t &addr, addr_t bus) noexcept
    { addr = set_bits(addr, mask, bus << from); }

    inline void dump(int level, addr_t val, std::string *msg = nullptr)
    { bfdebug_subnhex(level, name, get(val), msg); }
}

namespace rsvd
{
    constexpr const auto mask = 0x7F000000UL;
    constexpr const auto from = 24;
    constexpr const auto name = "reserved";

    inline auto get(addr_t addr) noexcept
    { return get_bits(addr, mask) >> from; }

    inline void set(addr_t &addr, addr_t rsvd) noexcept
    { addr = set_bits(addr, mask, rsvd << from); }

    inline void dump(int level, addr_t val, std::string *msg = nullptr)
    { bfdebug_subnhex(level, name, get(val), msg); }
}

namespace en
{
    constexpr const auto mask = 0x80000000UL;
    constexpr const auto from = 31;
    constexpr const auto name = "en";

    inline auto is_enabled(addr_t addr) noexcept
    { return is_bit_set(addr, from); }

    inline void enable(addr_t &addr) noexcept
    { addr = set_bit(addr, from); }

    inline void disable(addr_t &addr) noexcept
    { addr = clear_bit(addr, from); }

    inline void dump(int level, addr_t val, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(val), msg); }
}

inline void dump_addr(int level, addr_t addr, std::string *msg = nullptr)
{
    bfdebug_info(level, "PCI: portio config addr", msg);

    en::dump(level, addr, msg);
    bus::dump(level, addr, msg);
    dev::dump(level, addr, msg);
    fun::dump(level, addr, msg);
    reg::dump(level, addr, msg);
    off::dump(level, addr, msg);
}

inline addr_t read32(addr_t addr)
{ return ::x64::portio::ind(addr); }

inline addr_t read16(addr_t addr)
{ return ::x64::portio::inw(addr); }

inline addr_t read08(addr_t addr)
{ return ::x64::portio::inb(addr); }

inline void write32(addr_t addr, uint32_t data)
{ ::x64::portio::outd(addr, data); }

inline void write16(addr_t addr, uint16_t data)
{ ::x64::portio::outw(addr, data); }

inline void write08(addr_t addr, uint8_t data)
{ ::x64::portio::outb(addr, data); }

inline addr_t addr(
    addr_t bus,
    addr_t dev = 0,
    addr_t fun = 0,
    addr_t reg = 0,
    addr_t off = 0)
{
    addr_t ret = 0UL;

    off::set(ret, off);
    reg::set(ret, reg);
    fun::set(ret, fun);
    dev::set(ret, dev);
    bus::set(ret, bus);
    en::enable(ret);

    return ret;
}

inline addr_t read(addr_t addr)
{
    outd(0xCF8, addr);
    return ind(0xCFC);
}

enum header_t { standard, pci_bridge, cardbus_bridge };

inline auto header_type(addr_t cf8)
{
    reg::set(cf8, 3);
    outd(0xCF8, cf8);

    return (ind(0xCFC) & 0xFF0000) >> 16;
}

// For now just passthrough what linux needs: host, isa, pci
//
inline auto passthrough_bridge(addr_t cf8)
{
    reg::set(cf8, 3);
    outd(0xCF8, cf8);

    auto reg = ind(0xCFC);
    auto cc = (reg & 0xFF000000) >> 24;
    auto sc = (reg & 0x00FF0000) >> 16;

    return cc == 0x6 && (sc == 0 || sc == 1 || sc == 4 || sc == 9);
}

// --------------------------------------------------------------------------
// PCI capability structures (64-bit)
// --------------------------------------------------------------------------

using cap_id_t = enum cap_id { cap_id_msi = 0x5U, cap_id_msix = 0x11U };
using cap_action_t = delegate<void(addr_t, addr_t, uint32_t)>;

// MSI capability
//
struct msi_cap {
    uint8_t id;
    uint16_t msg_ctrl;
    uint32_t msg_addr_3100;
    uint32_t msg_addr_6332;
    uint16_t msg_data;
    uint16_t reserved;
};

// for_each_cap
//
// Call the provided action for each capability
// structure at the provided BDF
//
inline void for_each_cap(
    addr_t bus,
    addr_t dev,
    addr_t fun,
    const cap_action_t &action)
{
    addr_t next = addr(bus, dev, fun, 0xDUL);
    addr_t prev = next;

//    bfdebug_nhex(0, "next", next);
//    bfdebug_nhex(0, "prev", prev);

    outd(0xCF8, next);
    addr_t reg = inb(0xCFC) >> 2;
//    bfdebug_nhex(0, "reg", reg);

    while (reg != 0) {
        reg::set(next, reg);
        auto data = read(next);
        action(prev, next, data);
        reg = (data & 0xFF00UL) >> (8 + 2);
        prev = next;

//       bfdebug_nhex(0, "data", data);
//       bfdebug_nhex(0, "next", next);
//       bfdebug_nhex(0, "prev", prev);
//       bfdebug_nhex(0, "reg", reg);
    }
}
}

namespace eapis::intel_x64
{

class vcpu;

bool pci_config_in(
    ::intel_x64::pci::iocfg::addr_t cf8,
    eapis::intel_x64::io_instruction_handler::info_t &info);

bool pci_config_out(
    ::intel_x64::pci::iocfg::addr_t cf8,
    eapis::intel_x64::io_instruction_handler::info_t &info);

class pci_handler
{
public:

    using addr_t = ::intel_x64::pci::iocfg::addr_t;
    using info_t = ::eapis::intel_x64::io_instruction_handler::info_t;
    using hdlr_t = delegate<bool(gsl::not_null<vcpu_t *>, info_t&, addr_t)>;

    // Users pass two arguments to add a PCI handler:
    //
    //  1) A predicate that is a function of the last value programmed into
    //     0xCF8 and the information provided by the io_instruction_handler
    //  2) A delegate to call if the predicate returns true;
    //
    // When a configuration access occurs, this class will start at the
    // most-recently added handler and call its predicate. If it returns true,
    // then the associated handler is called, otherwise it continues to the
    // next predicate. This allows callers with the flexibility needed for
    // fine-grained PCI device emulation. For example, if you wish to
    // passthrough reads to every PCI bridge and every register at the BDF
    // 02:00:00, then you could register e.g. (pseudocode):
    //
    // auto call_me = [&] (addr_t cf8, info_t info) {
    //     return is_bridge(cf8) || bdf(cf8) == 2,0,0;
    // };
    //
    // bool handle_read(vcpu_t *, info_t &)
    // {
    //     ...
    // }
    //
    // add_read_handler(call_me, handle_read);
    //
    // Note that the first time any predicate returns true, it calls
    // the handler and returns without any further processing.
    //
    using pred_t = delegate<bool(addr_t, info_t&)>;

    pci_handler(gsl::not_null<vcpu *> vcpu);
    ~pci_handler() = default;

    void add_in_handler(const pred_t &p, const hdlr_t &h);
    void add_out_handler(const pred_t &p, const hdlr_t &h);

    bool handle_in_alert(gsl::not_null<vcpu_t *> vcpu, info_t &info);
    bool handle_in_addr(gsl::not_null<vcpu_t *> vcpu, info_t &info);
    bool handle_in_data(gsl::not_null<vcpu_t *> vcpu, info_t &info);

    bool handle_out_alert(gsl::not_null<vcpu_t *> vcpu, info_t &info);
    bool handle_out_addr(gsl::not_null<vcpu_t *> vcpu, info_t &info);
    bool handle_out_data(gsl::not_null<vcpu_t *> vcpu, info_t &info);

private:

    vcpu *m_vcpu{};
    addr_t m_cf8{};

    std::list<std::pair<pred_t, hdlr_t>> m_in_list;
    std::list<std::pair<pred_t, hdlr_t>> m_out_list;
};
}

#endif
