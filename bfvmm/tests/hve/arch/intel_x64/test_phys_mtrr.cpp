//
// Bareflank Extended APIs
//
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

#include <array>

#include <arch/x64/misc.h>
#include <arch/intel_x64/cpuid.h>
#include <hve/arch/intel_x64/mtrr.h>
#include <hve/arch/intel_x64/phys_mtrr.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

using namespace ::x64::cpuid;
using namespace ::intel_x64::cpuid;
using namespace ::intel_x64::mtrr;
using namespace eapis::intel_x64::mtrr;

static const std::array<uint64_t, 5U> mtrr_type = {{
    uncacheable,
    write_combining,
    write_through,
    write_protected,
    write_back
}};

static const std::array<::intel_x64::msrs::field_type, 11U> fixed_addrs = {{
    fix64k_00000::addr,
    fix16k_80000::addr,
    fix16k_A0000::addr,
    fix4k_C0000::addr,
    fix4k_C8000::addr,
    fix4k_D0000::addr,
    fix4k_D8000::addr,
    fix4k_E0000::addr,
    fix4k_E8000::addr,
    fix4k_F0000::addr,
    fix4k_F8000::addr
}};

void enable_mtrr()
{
    g_edx_cpuid[feature_information::addr] |=
        feature_information::edx::mtrr::mask;  // expose through cpuid
    g_eax_cpuid[addr_size::addr] = 39U;        // phys addr size

    ia32_mtrr_def_type::e::enable();           // enable MTRRs
    ia32_mtrr_def_type::fe::enable();          // enable fixed ranges

    g_msrs[ia32_mtrrcap::addr] = (1U << 11U);  // enable smrr support
    g_msrs[ia32_mtrrcap::addr] |= (1U << 10U); // enable wc support
    g_msrs[ia32_mtrrcap::addr] |= (1U << 8U);  // enable fixed support
    g_msrs[ia32_mtrrcap::addr] |= 1U;          // set vcnt to 1
}

static uint64_t init_multi_fixed()
{
    expects(mtrr_type.size() == 5U);

    uint64_t val = 0U;
    for (auto j = 0U; j < mtrr_type.size(); ++j) {
        val |= mtrr_type.at(j) << (j << 3U);
    }

    return val;
}

static bool
check_fixed_ranges(phys_mtrr &&mtrr, uint64_t *base, size_t regs, size_t size)
{
    for (uint64_t b = 0U; b < regs; ++b) {
        for (auto i = 0U; i < 8U; ++i) {
            auto addr = base[b] + (i * size);
            if (i < 5U) {
                if (mtrr.mem_type(addr) != mtrr_type.at(i)) {
                    return false;
                }
                continue;
            }

            if (mtrr.mem_type(addr) != uncacheable) {
                return false;
            }
        }
    }

    return true;
}

static bool check_64kb_ranges(phys_mtrr &&mtrr)
{
    constexpr auto regs = 1U;
    constexpr auto size = (1U << 16U);
    std::array<uint64_t, regs> base = {0x00000U};

    return check_fixed_ranges(std::move(mtrr), base.data(), regs, size);
}

static bool check_16kb_ranges(phys_mtrr &&mtrr)
{
    constexpr auto regs = 2U;
    constexpr auto size = (1U << 14U);
    std::array<uint64_t, regs> base = {0x80000U, 0xA0000U};

    return check_fixed_ranges(std::move(mtrr), base.data(), regs, size);
}

static bool check_4kb_ranges(phys_mtrr &&mtrr)
{
    constexpr auto regs = 8U;
    constexpr auto size = (1U << 12U);
    std::array<uint64_t, regs> base = {
        0xC0000U, 0xC8000U, 0xD0000U, 0xD8000U,
        0xE0000U, 0xE8000U, 0xF0000U, 0xF8000U
    };

    return check_fixed_ranges(std::move(mtrr), base.data(), regs, size);
}

TEST_CASE("phys_mtrr: constructor")
{
    g_edx_cpuid[feature_information::addr] = 0U;
    CHECK_THROWS(phys_mtrr());

    g_edx_cpuid[feature_information::addr] = ~0U;
    ia32_mtrr_def_type::e::disable();
    CHECK_THROWS(phys_mtrr());

    ia32_mtrr_def_type::e::enable();
    g_eax_cpuid[addr_size::addr] = 0U;
    CHECK_THROWS(phys_mtrr());

    g_eax_cpuid[addr_size::addr] = 39U;
    uint64_t base = 0xFFFFFFFFFFFFFFFFU;
    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    CHECK_THROWS(phys_mtrr());

    uint64_t mask = 0xFFFFFFFFFFFFFFFFU;
    base = 0x10000U;
    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    ::intel_x64::msrs::set(ia32_physmask::start_addr, mask);
    CHECK_THROWS(phys_mtrr());

    base |= 0xFFU;
    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    CHECK_THROWS(phys_mtrr());

    base = 0x080000U;
    mask = size_to_mask(0x1000U, 39U) | (1U << 11U);
    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    ::intel_x64::msrs::set(ia32_physmask::start_addr, mask);

    g_msrs[ia32_mtrrcap::addr] = 1U;
    ia32_mtrr_def_type::type::set(write_back);
    CHECK_NOTHROW(phys_mtrr());
}

TEST_CASE("phys_mtrr: ia32_mtrrcap fields")
{
    enable_mtrr();
    auto mtrr = phys_mtrr();

    CHECK(mtrr.variable_count() == 1U);
    CHECK(mtrr.fixed_count() == 11U);
    CHECK(mtrr.enabled());
    CHECK(mtrr.fixed_enabled());
    CHECK(mtrr.wc_supported());
    CHECK(mtrr.fixed_supported());
    CHECK(mtrr.smrr_supported());
}

TEST_CASE("phys_mtrr: mem_type - fixed, single type")
{
    enable_mtrr();

    for (const uint64_t type : mtrr_type) {
        for (auto i = 0U; i < 11U; ++i) {
            uint64_t val = 0U;

            /// Assign the same type to all ranges
            for (uint64_t j = 0U; j < 8U; ++j) {
                val |= type << (j << 3U);
            }
            ::intel_x64::msrs::set(fixed_addrs.at(i), val);
        }

        auto mtrr = phys_mtrr();
        CHECK(mtrr.fixed_enabled());

        for (auto i = 0U; i < phys_mtrr::s_fixed_size; i += 0x1000U) {
            CHECK(mtrr.mem_type(i) == type);
        }
    }
}

TEST_CASE("phys_mtrr: mem_type - fixed, 64KB, multi-type")
{
    enable_mtrr();
    auto val = init_multi_fixed();

    ::intel_x64::msrs::set(fix64k_00000::addr, val);

    auto mtrr = phys_mtrr();
    CHECK(mtrr.fixed_enabled());
    CHECK(check_64kb_ranges(std::move(mtrr)));
}

TEST_CASE("phys_mtrr: mem_type - fixed, 16KB, multi-type")
{
    enable_mtrr();
    auto val = init_multi_fixed();

    ::intel_x64::msrs::set(fix16k_80000::addr, val);
    ::intel_x64::msrs::set(fix16k_A0000::addr, val);

    auto mtrr = phys_mtrr();
    CHECK(mtrr.fixed_enabled());
    CHECK(check_16kb_ranges(std::move(mtrr)));
}

TEST_CASE("phys_mtrr: mem_type - fixed, 4KB, multi-type")
{
    enable_mtrr();
    auto val = init_multi_fixed();

    ::intel_x64::msrs::set(fix4k_C0000::addr, val);
    ::intel_x64::msrs::set(fix4k_C8000::addr, val);
    ::intel_x64::msrs::set(fix4k_D0000::addr, val);
    ::intel_x64::msrs::set(fix4k_D8000::addr, val);
    ::intel_x64::msrs::set(fix4k_E0000::addr, val);
    ::intel_x64::msrs::set(fix4k_E8000::addr, val);
    ::intel_x64::msrs::set(fix4k_F0000::addr, val);
    ::intel_x64::msrs::set(fix4k_F8000::addr, val);

    auto mtrr = phys_mtrr();
    CHECK(mtrr.fixed_enabled());
    CHECK(check_4kb_ranges(std::move(mtrr)));
}

TEST_CASE("phys_mtrr: mem_type - variable")
{
    enable_mtrr();

    uint64_t physbase = 0U;
    uint64_t physmask = 0U;
    uint64_t pas = g_eax_cpuid[addr_size::addr];
    uint64_t mask = size_to_mask(0x2000U, pas);

    ia32_physbase::physbase::set(physbase, 0x800000U, pas);
    ia32_physmask::physmask::set(physmask, mask, pas);
    ia32_physmask::valid::enable(physmask);

    msrs_n::set(ia32_physmask::start_addr, physmask);
    std::array<uint64_t, 3U> invalid_mtrr_type = {2U, 3U, 7U};

    for (auto type : invalid_mtrr_type) {
        ia32_physbase::type::set(physbase, type);
        msrs_n::set(ia32_physbase::start_addr, physbase);
        CHECK_THROWS(phys_mtrr());
    }

    for (auto type : mtrr_type) {
        ia32_physbase::type::set(physbase, type);
        msrs_n::set(ia32_physbase::start_addr, physbase);

        auto mtrr = phys_mtrr();
        CHECK(mtrr.mem_type(0x800000000U) == type);
    }
}

TEST_CASE("phys_mtrr: range_list throws")
{
    enable_mtrr();
    std::vector<mtrr::range> list;
    auto mtrr = phys_mtrr();

    CHECK_THROWS(mtrr.range_list(0, 0x0000, list));
    CHECK_THROWS(mtrr.range_list(1, 0x1000, list));
    CHECK_THROWS(mtrr.range_list(0, 0x1002, list));
    CHECK_THROWS(mtrr.range_list(~0ULL, 0x1000, list));
}

TEST_CASE("phys_mtrr: range_list over fixed")
{
    enable_mtrr();
    std::vector<mtrr::range> list;
    auto val = init_multi_fixed();

    ::intel_x64::msrs::set(fix64k_00000::addr, val);

    auto mtrr = phys_mtrr();
    mtrr.range_list(0, 8 * (1U << 16U), list);
    CHECK(list.size() == 6U);

    for (auto i = 0U; i < 5U; ++i) {
        CHECK(list[i].base == i * (1U << 16U));
        CHECK(list[i].size == (1U << 16U));
    }

    CHECK(list[5].base == 5 * (1U << 16U));
    CHECK(list[5].size == 3 * (1U << 16U));

    CHECK(list[0].type == uncacheable);
    CHECK(list[1].type == write_combining);
    CHECK(list[2].type == write_through);
    CHECK(list[3].type == write_protected);
    CHECK(list[4].type == write_back);
    CHECK(list[5].type == uncacheable);
}

TEST_CASE("phys_mtrr: range_list over variable")
{
    enable_mtrr();

    std::array<uint64_t, 3U> type = {
        uncacheable, write_protected, write_through
    };
    std::array<uint64_t, 3U> size = {
        0x1000U, 0x4000U, 0x40000000U
    };
    std::array<uintptr_t, 3U> base = {
        0x100000U, 0x204000U, 0x40000000U
    };
    expects(base.size() == size.size() && size.size() == type.size());

    for (auto i = 0U; i < base.size(); ++i) {
        uint64_t physbase = 0U;
        uint64_t physmask = 0U;
        uint64_t pas = g_eax_cpuid[addr_size::addr];
        uint64_t mask = size_to_mask(size[i], pas);

        ia32_physbase::type::set(physbase, type[i]);
        ia32_physbase::physbase::set(physbase, base[i] >> 12U, pas);

        ia32_physmask::valid::enable(physmask);
        ia32_physmask::physmask::set(physmask, mask >> 12U, pas);

        msrs_n::set(ia32_physbase::start_addr + (i * 2U), physbase);
        msrs_n::set(ia32_physmask::start_addr + (i * 2U), physmask);
    }

    uint64_t cap = ia32_mtrrcap::get();
    g_msrs[ia32_mtrrcap::addr] = (cap & ~0xFFULL) | base.size();
    ia32_mtrr_def_type::type::set(write_back);

    auto mtrr = phys_mtrr();
    std::vector<mtrr::range> list{0};
    mtrr.range_list(base[0], (base[2] + size[2]) - base[0], list);

    CHECK(list.size() == 5U); // 3 explicit ranges + 2 holes
    CHECK(list[0].base == base[0]);
    CHECK(list[0].size == size[0]);
    CHECK(list[0].type == type[0]);

    CHECK(list[1].base == list[0].base + list[0].size);
    CHECK(list[1].size == base[1] - list[1].base);
    CHECK(list[1].type == write_back);

    CHECK(list[2].base == base[1]);
    CHECK(list[2].size == size[1]);
    CHECK(list[2].type == type[1]);

    CHECK(list[3].base == list[2].base + list[2].size);
    CHECK(list[3].size == base[2] - list[3].base);
    CHECK(list[3].type == write_back);

    CHECK(list[4].base == base[2]);
    CHECK(list[4].size == size[2]);
    CHECK(list[4].type == type[2]);
}

}
}

#endif
