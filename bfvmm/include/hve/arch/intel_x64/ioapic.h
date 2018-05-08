//
// Bareflank Hypervisor
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

#ifndef IOAPIC_INTEL_X64_H
#define IOAPIC_INTEL_X64_H

#include <cstdint>
#include <bfdebug.h>
#include <bfbitmanip.h>
#include <arch/intel_x64/apic/lapic.h>

namespace eapis
{
namespace intel_x64
{

/// IOAPIC intrinsics
///
/// The IOAPIC is memory-mapped to 0xFEC0000 by default, though
/// this may be relocated. Like the xAPIC, it is accessed in 32-bit
/// loads and stores.
///
/// See chapter 3 of the IOAPIC spec for more details
///
namespace ioapic
{
    /// redirection table entry (rte) type
    using rte_t = uint64_t;

    /// offset type
    using offset_t = uint8_t;

    /// value type
    using value_t = uint32_t;

    /// base address type
    using base_t = uintptr_t;

    inline auto align_base(const base_t addr)
    { return addr & 0xFFFFFFFFFFFFFFF0ULL; }

    /// @cond

    namespace id
    {
        constexpr const auto offset = 0U;
        constexpr const auto default_val = 0U;
        constexpr const auto mask = 0x0F000000U;
        constexpr const auto from = 24U;
        constexpr const auto name = "id";

        inline value_t get(value_t reg)
        { return get_bits(reg, mask) >> from; }

        inline value_t set(value_t reg, value_t id)
        { return set_bits(reg, mask, (id << from)); }

        inline void dump(int level, value_t reg, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(reg), msg); }
    }

    namespace ver
    {
        constexpr const auto offset = 1U;
        constexpr const auto default_val = 0x00170011U;
        constexpr const auto name = "ver";

        namespace version
        {
            constexpr const auto mask = 0xFFU;
            constexpr const auto from = 0U;
            constexpr const auto name = "version";

            inline value_t get(value_t reg)
            { return get_bits(reg, mask) >> from; }

            inline value_t set(value_t reg, value_t ver)
            { return set_bits(reg, mask, (ver << from)); }

            inline void dump(int level, value_t reg, std::string *msg = nullptr)
            { bfdebug_subndec(level, name, get(reg), msg); }
        }

        namespace max_rte_number
        {
            constexpr const auto mask = 0xFF0000U;
            constexpr const auto from = 16U;
            constexpr const auto name = "max_rte_number";

            inline value_t get(value_t reg)
            { return get_bits(reg, mask) >> from; }

            inline value_t set(value_t reg, value_t ver)
            { return set_bits(reg, mask, (ver << from)); }

            inline void dump(int level, value_t reg, std::string *msg = nullptr)
            { bfdebug_subndec(level, name, get(reg), msg); }
        }

        inline void dump(int level, value_t reg, std::string *msg = nullptr)
        {
            version::dump(level, reg, msg);
            max_rte_number::dump(level, reg, msg);
        }
    }

    namespace arb
    {
        constexpr const auto offset = 2U;
        constexpr const auto default_val = 0x0U;
        constexpr const auto name = "arb";

        namespace id
        {
            constexpr const auto mask = 0x0F000000U;
            constexpr const auto from = 24U;
            constexpr const auto name = "id";

            inline value_t get(value_t reg)
            { return get_bits(reg, mask) >> from; }

            inline value_t set(value_t reg, value_t arb)
            { return set_bits(reg, mask, (arb << from)); }

            inline void dump(int level, value_t reg, std::string *msg = nullptr)
            { bfdebug_subndec(level, name, get(reg), msg); }
        }

        inline void dump(int level, value_t reg, std::string *msg = nullptr)
        { id::dump(level, reg, msg); }
    }

    namespace rte
    {
        constexpr const auto name = "rte";
        constexpr const auto count = 24U;

        namespace vector
        {
            constexpr const auto mask = 0x00000000000000FFU;
            constexpr const auto from = 0U;
            constexpr const auto name = "vector";
            constexpr const auto min = 0x10U;
            constexpr const auto max = 0xFEU;

            inline auto get(rte_t val) noexcept
            { return get_bits(val, mask) >> from; }

            inline auto set(rte_t reg, rte_t val) noexcept
            { return set_bits(reg, mask, val << from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            { bfdebug_subnhex(lev, name, get(val), msg); }
        }

        namespace delivery_mode
        {
            constexpr const auto mask = 0x0000000000000700U;
            constexpr const auto from = 8U;
            constexpr const auto name = "delivery_mode";

            constexpr const auto fixed = 0U;
            constexpr const auto lowest_priority = 1U;
            constexpr const auto smi = 2U;
            constexpr const auto nmi = 4U;
            constexpr const auto init = 5U;
            constexpr const auto extint = 7U;

            inline auto get(rte_t val) noexcept
            { return get_bits(val, mask) >> from; }

            inline auto set(rte_t reg, rte_t val) noexcept
            { return set_bits(reg, mask, val << from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            {
                const auto mode = get(val);
                if (mode == lowest_priority) {
                    bfdebug_subtext(lev, name, "lowest_priority", msg);
                    return;
                }

                ::intel_x64::lapic::dump_delivery_mode(lev, get(val), msg);
            }
        }

        namespace destination_mode
        {
            constexpr const auto mask = 0x0000000000000800U;
            constexpr const auto from = 11U;
            constexpr const auto name = "destination_mode";

            constexpr const auto physical = 0U;
            constexpr const auto logical = 1U;

            inline auto get(rte_t val) noexcept
            { return get_bits(val, mask) >> from; }

            inline auto set(rte_t reg, rte_t val) noexcept
            { return set_bits(reg, mask, val << from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            {
                if (get(val) == physical) {
                    bfdebug_subtext(lev, name, "physical", msg);
                    return;
                }

                bfdebug_subtext(lev, name, "logical", msg);
            }
        }

        namespace delivery_status
        {
            constexpr const auto mask = 0x0000000000001000U;
            constexpr const auto from = 12U;
            constexpr const auto name = "delivery_status";

            constexpr const auto idle = 0U;
            constexpr const auto send_pending = 1U;

            inline auto get(rte_t val) noexcept
            { return get_bits(val, mask) >> from; }

            inline auto set(rte_t reg, rte_t val) noexcept
            { return set_bits(reg, mask, val << from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            { ::intel_x64::lapic::dump_delivery_status(lev, get(val), msg); }
        }

        namespace polarity
        {
            constexpr const auto mask = 0x0000000000002000U;
            constexpr const auto from = 13U;
            constexpr const auto name = "polarity";

            constexpr const auto active_high = 0U;
            constexpr const auto active_low = 1U;

            inline auto get(rte_t val) noexcept
            { return get_bits(val, mask) >> from; }

            inline auto set(rte_t reg, rte_t val) noexcept
            { return set_bits(reg, mask, val << from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            {
                if (get(val) == active_high) {
                    bfdebug_subtext(lev, name, "active_high", msg);
                    return;
                }

                bfdebug_subtext(lev, name, "active_low", msg);
            }
        }

        namespace remote_irr
        {
            constexpr const auto mask = 0x0000000000004000U;
            constexpr const auto from = 14U;
            constexpr const auto name = "remote_irr";

            inline auto is_enabled(rte_t val)
            { return is_bit_set(val, from); }

            inline auto is_disabled(rte_t val)
            { return is_bit_cleared(val, from); }

            inline auto enable(rte_t val)
            { return set_bit(val, from); }

            inline auto disable(rte_t val)
            { return clear_bit(val, from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            { bfdebug_subbool(lev, name, is_enabled(val), msg); }
        }

        namespace trigger_mode
        {
            constexpr const auto mask = 0x0000000000008000U;
            constexpr const auto from = 15U;
            constexpr const auto name = "trigger_mode";

            constexpr const auto edge = 0U;
            constexpr const auto level = 1U;

            inline auto get(rte_t val) noexcept
            { return get_bits(val, mask) >> from; }

            inline auto set(rte_t reg, rte_t val) noexcept
            { return set_bits(reg, mask, val << from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            {
                if (get(val) == edge) {
                    bfdebug_subtext(lev, name, "edge", msg);
                    return;
                }

                bfdebug_subtext(lev, name, "level", msg);
            }
        }

        namespace mask_bit
        {
            constexpr const auto mask = 0x0000000000010000U;
            constexpr const auto from = 16U;
            constexpr const auto name = "mask_bit";

            inline auto is_enabled(rte_t val)
            { return is_bit_set(val, from); }

            inline auto is_disabled(rte_t val)
            { return is_bit_cleared(val, from); }

            inline auto enable(rte_t val)
            { return set_bit(val, from); }

            inline auto disable(rte_t val)
            { return clear_bit(val, from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            { bfdebug_subbool(lev, name, is_enabled(val), msg); }
        }

        namespace logical_destination
        {
            constexpr const auto mask = 0xFF00000000000000U;
            constexpr const auto from = 56U;
            constexpr const auto name = "logical_destination";

            inline auto get(rte_t val) noexcept
            { return get_bits(val, mask) >> from; }

            inline auto set(rte_t reg, rte_t val) noexcept
            { return set_bits(reg, mask, val << from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            { bfdebug_subnhex(lev, name, get(val), msg); }
        }

        namespace physical_destination
        {
            constexpr const auto mask = 0x0F00000000000000U;
            constexpr const auto from = 56U;
            constexpr const auto name = "physical_destination";

            inline auto get(rte_t val) noexcept
            { return get_bits(val, mask) >> from; }

            inline auto set(rte_t reg, rte_t val) noexcept
            { return set_bits(reg, mask, val << from); }

            inline void dump(int lev, rte_t val, std::string *msg = nullptr)
            { bfdebug_subnhex(lev, name, get(val), msg); }
        }

        inline void dump(int lev, rte_t val, std::string *msg = nullptr)
        {
            bfdebug_nhex(lev, name, val,  msg);
            vector::dump(lev, val, msg);
            delivery_status::dump(lev, val, msg);
            polarity::dump(lev, val, msg);
            remote_irr::dump(lev, val, msg);
            trigger_mode::dump(lev, val, msg);
            mask_bit::dump(lev, val, msg);
            logical_destination::dump(lev, val, msg);
            physical_destination::dump(lev, val, msg);
        }
    }

    inline bool exists(const offset_t offset)
    { return (offset < 0x3U) || (offset >= 0x10U && offset < 0x40U); }

    inline bool is_read_only(const offset_t offset)
    { return offset == ver::offset || offset == arb::offset; }

    inline bool is_read_write(const offset_t offset)
    { return exists(offset) && !is_read_only(offset); }

    inline bool is_readable(const offset_t offset)
    { return is_read_write(offset) || is_read_only(offset); }

    inline bool is_writable(const offset_t offset)
    { return is_read_write(offset); }

    /// @endcond
}
}
}

#endif
