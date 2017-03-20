//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <gsl/gsl>
#include <bitmanip_ext.h>

#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/map_ptr_x64.h>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>
#include <vmcs/ept_entry_intel_x64.h>
#include <vmcs/root_ept_intel_x64.h>

#ifdef ECR_DEBUG
#define verbose true
#else
#define verbose false
#endif

using namespace intel_x64;
using namespace vmcs;

namespace exec_ctls1 = primary_processor_based_vm_execution_controls;
namespace exec_ctls2 = secondary_processor_based_vm_execution_controls;

std::unique_ptr<root_ept_intel_x64> g_ept;
std::unique_ptr<std::vector<uint64_t>> g_trap_list;
std::unique_ptr<std::vector<uint64_t>> g_split_list;
std::mutex g_ept_mtx;

vmcs_intel_x64_eapis::vmcs_intel_x64_eapis()
{
    static intel_x64::vmcs::value_type g_vpid = 1;
    m_vpid = g_vpid++;
}

void
vmcs_intel_x64_eapis::write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                                   gsl::not_null<vmcs_intel_x64_state *> guest_state)
{
    static bool init_ept = true;

    vmcs_intel_x64::write_fields(host_state, guest_state);

    this->disable_ept();
    this->disable_vpid();
    this->enable_io_bitmaps();
    this->enable_msr_bitmap();

    if (init_ept) {
        g_trap_list = std::make_unique<std::vector<uint64_t>>();
        g_trap_list->reserve(TRAP_LIST_SZ);

        g_split_list = std::make_unique<std::vector<uint64_t>>();
        g_split_list->reserve(SPLIT_LIST_SZ);

        g_ept = std::make_unique<root_ept_intel_x64>();
        g_ept->setup_identity_map_2m(0, PHYS_MEM_SZ);

        init_ept = false;
    }

    set_eptp(g_ept->eptp());
}

void
vmcs_intel_x64_eapis::enable_ept()
{
    exec_ctls2::enable_ept::enable();
    intel_x64::vmx::invept_global();
}

void
vmcs_intel_x64_eapis::disable_ept()
{
    intel_x64::vmx::invept_global();
    exec_ctls2::enable_ept::disable();

    ept_pointer::set(0UL);
}

void
vmcs_intel_x64_eapis::set_eptp(integer_pointer eptp)
{
    auto &&entry = ept_entry_intel_x64{&eptp};

    ept_pointer::memory_type::set(ept_pointer::memory_type::write_back);
    ept_pointer::page_walk_length_minus_one::set(3UL);
    ept_pointer::phys_addr::set(entry.phys_addr());
}

void
vmcs_intel_x64_eapis::enable_io_bitmaps()
{
    m_io_bitmapa = std::make_unique<uint8_t[]>(x64::page_size);
    m_io_bitmapb = std::make_unique<uint8_t[]>(x64::page_size);
    m_io_bitmapa_view = gsl::make_span(m_io_bitmapa, x64::page_size);
    m_io_bitmapb_view = gsl::make_span(m_io_bitmapb, x64::page_size);

    address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(m_io_bitmapa.get()));
    address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(m_io_bitmapb.get()));

    exec_ctls1::use_io_bitmaps::enable();
    pass_through_all_io_accesses();
}

void
vmcs_intel_x64_eapis::disable_io_bitmaps()
{
    exec_ctls1::use_io_bitmaps::disable();

    address_of_io_bitmap_a::set(0UL);
    address_of_io_bitmap_b::set(0UL);

    m_io_bitmapa_view = gsl::span<uint8_t>(nullptr);
    m_io_bitmapb_view = gsl::span<uint8_t>(nullptr);
    m_io_bitmapa.reset();
    m_io_bitmapb.reset();
}

void
vmcs_intel_x64_eapis::trap_on_io_access(port_type port)
{
    if (!m_io_bitmapa || !m_io_bitmapb)
        throw std::runtime_error("io bitmaps not enabled");

    if (port < 0x8000)
    {
        auto &&addr = port;
        set_bit_from_span(m_io_bitmapa_view, addr);
    }
    else
    {
        auto &&addr = port - 0x8000;
        set_bit_from_span(m_io_bitmapb_view, addr);
    }
}

void
vmcs_intel_x64_eapis::trap_on_all_io_accesses()
{
    if (!m_io_bitmapa || !m_io_bitmapb)
        throw std::runtime_error("io bitmaps not enabled");

    __builtin_memset(m_io_bitmapa.get(), 0xFF, x64::page_size);
    __builtin_memset(m_io_bitmapb.get(), 0xFF, x64::page_size);
}

void
vmcs_intel_x64_eapis::pass_through_io_access(port_type port)
{
    if (!m_io_bitmapa || !m_io_bitmapb)
        throw std::runtime_error("io bitmaps not enabled");

    if (port < 0x8000)
    {
        auto &&addr = port;
        clear_bit_from_span(m_io_bitmapa_view, addr);
    }
    else
    {
        auto &&addr = port - 0x8000;
        clear_bit_from_span(m_io_bitmapb_view, addr);
    }
}

void
vmcs_intel_x64_eapis::pass_through_all_io_accesses()
{
    if (!m_io_bitmapa || !m_io_bitmapb)
        throw std::runtime_error("io bitmaps not enabled");

    __builtin_memset(m_io_bitmapa.get(), 0, x64::page_size);
    __builtin_memset(m_io_bitmapb.get(), 0, x64::page_size);
}

/// Note:
///
/// For context, here is the text from the SDM.
///
/// - Read bitmap for low MSRs (located at the MSR-bitmap address):
///   This contains one bit for each MSR address in the range 00000000H to
///   00001FFFH. The bit determines whether an execution of RDMSR applied to
///   that MSR causes a VM exit.
///
/// - Read bitmap for high MSRs (located at the MSR-bitmap address plus 1024).
///   This contains one bit for each MSR address in the range C0000000H to
///   C0001FFFH. The bit determines whether an execution of RDMSR applied to
///   that MSR causes a VM exit.
///
/// - Write bitmap for low MSRs (located at the MSR-bitmap address plus 2048).
///   This contains one bit for each MSR address in the range 00000000H to
///   00001FFFH. The bit determines whether an execution of WRMSR applied to
///   that MSR causes a VM exit.
///
/// - Write bitmap for high MSRs (located at the MSR-bitmap address plus 3072).
///   This contains one bit for each MSR address in the range C0000000H to
///   C0001FFFH. The bit determines whether an execution of WRMSR applied to
///   that MSR causes a VM exit.
///

void
vmcs_intel_x64_eapis::enable_msr_bitmap()
{
    m_msr_bitmap = std::make_unique<uint8_t[]>(x64::page_size);
    m_msr_bitmap_view = gsl::make_span(m_msr_bitmap, x64::page_size);

    address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
    exec_ctls1::use_msr_bitmap::enable();

    pass_through_all_rdmsr_accesses();
    pass_through_all_wrmsr_accesses();
}

void
vmcs_intel_x64_eapis::disable_msr_bitmap()
{
    exec_ctls1::use_msr_bitmap::disable();
    address_of_msr_bitmap::set(0UL);

    m_msr_bitmap_view = gsl::span<uint8_t>(nullptr);
    m_msr_bitmap.reset();
}

void
vmcs_intel_x64_eapis::trap_on_rdmsr_access(msr_type msr)
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    if (msr <= 0x00001FFFUL)
    {
        auto &&addr = (msr - 0x00000000UL) + 0;
        return set_bit_from_span(m_msr_bitmap_view, addr);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL)
    {
        auto &&addr = (msr - 0xC0000000UL) + 0x2000;
        return set_bit_from_span(m_msr_bitmap_view, addr);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
vmcs_intel_x64_eapis::trap_on_wrmsr_access(msr_type msr)
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    if (msr <= 0x00001FFFUL)
    {
        auto &&addr = (msr - 0x00000000UL) + 0x4000;
        return set_bit_from_span(m_msr_bitmap_view, addr);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL)
    {
        auto &&addr = (msr - 0xC0000000UL) + 0x6000;
        return set_bit_from_span(m_msr_bitmap_view, addr);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
vmcs_intel_x64_eapis::trap_on_all_rdmsr_accesses()
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    __builtin_memset(&m_msr_bitmap_view[0], 0xFF, x64::page_size / 2);
}

void
vmcs_intel_x64_eapis::trap_on_all_wrmsr_accesses()
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    __builtin_memset(&m_msr_bitmap_view[2048], 0xFF, x64::page_size / 2);
}

void
vmcs_intel_x64_eapis::pass_through_rdmsr_access(msr_type msr)
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    if (msr <= 0x00001FFFUL)
    {
        auto &&addr = (msr - 0x00000000) + 0;
        return clear_bit_from_span(m_msr_bitmap_view, addr);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL)
    {
        auto &&addr = (msr - 0xC0000000UL) + 0x2000;
        return clear_bit_from_span(m_msr_bitmap_view, addr);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
vmcs_intel_x64_eapis::pass_through_wrmsr_access(msr_type msr)
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    if (msr <= 0x00001FFFUL)
    {
        auto &&addr = (msr - 0x00000000UL) + 0x4000;
        return clear_bit_from_span(m_msr_bitmap_view, addr);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL)
    {
        auto &&addr = (msr - 0xC0000000UL) + 0x6000;
        return clear_bit_from_span(m_msr_bitmap_view, addr);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
vmcs_intel_x64_eapis::pass_through_all_rdmsr_accesses()
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    __builtin_memset(&m_msr_bitmap_view[0], 0x0, x64::page_size / 2);
}

void
vmcs_intel_x64_eapis::pass_through_all_wrmsr_accesses()
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    __builtin_memset(&m_msr_bitmap_view[2048], 0x0, x64::page_size / 2);
}

void
vmcs_intel_x64_eapis::enable_vpid()
{
    vmcs::virtual_processor_identifier::set(m_vpid);
    exec_ctls2::enable_vpid::enable();
}

void
vmcs_intel_x64_eapis::disable_vpid()
{
    vmcs::virtual_processor_identifier::set(0UL);
    exec_ctls2::enable_vpid::disable();
}

void
vmcs_intel_x64_eapis::trap_on_rdrand()
{ exec_ctls2::rdrand_exiting::enable_if_allowed(true); }

void
vmcs_intel_x64_eapis::pass_through_on_rdrand()
{ exec_ctls2::rdrand_exiting::disable(); }

void
vmcs_intel_x64_eapis::trap_on_rdseed()
{ exec_ctls2::rdseed_exiting::enable_if_allowed(true); }

void
vmcs_intel_x64_eapis::pass_through_on_rdseed()
{ exec_ctls2::rdseed_exiting::disable(); }

void
vmcs_intel_x64_eapis::trap_on_wbinvd()
{ exec_ctls2::wbinvd_exiting::enable_if_allowed(true); }

void
vmcs_intel_x64_eapis::pass_through_on_wbinvd()
{ exec_ctls2::wbinvd_exiting::disable(); }

void
vmcs_intel_x64_eapis::trap_on_rdpmc()
{ exec_ctls1::rdpmc_exiting::enable(); }

void
vmcs_intel_x64_eapis::pass_through_on_rdpmc()
{ exec_ctls1::rdpmc_exiting::disable(); }

void
vmcs_intel_x64_eapis::trap_on_rdtsc()
{ exec_ctls1::rdtsc_exiting::enable(); }

void
vmcs_intel_x64_eapis::pass_through_on_rdtsc()
{ exec_ctls1::rdtsc_exiting::disable(); }

void
vmcs_intel_x64_eapis::trap_on_invlpg()
{ exec_ctls1::invlpg_exiting::enable(); }

void
vmcs_intel_x64_eapis::pass_through_on_invlpg()
{ exec_ctls1::invlpg_exiting::disable(); }

void
vmcs_intel_x64_eapis::trap_on_desc_table()
{ exec_ctls2::descriptor_table_exiting::enable_if_allowed(verbose); }

void
vmcs_intel_x64_eapis::pass_through_on_desc_table()
{ exec_ctls2::descriptor_table_exiting::disable(); }

void
vmcs_intel_x64_eapis::trap_on_cr3_store()
{ exec_ctls1::cr3_store_exiting::enable(); }

void
vmcs_intel_x64_eapis::pass_through_on_cr3_store()
{ exec_ctls1::cr3_store_exiting::disable_if_allowed(verbose); }

void
vmcs_intel_x64_eapis::trap_on_cr3_load()
{
    exec_ctls1::cr3_load_exiting::enable();
    vmcs::cr3_target_count::set(0U);
}

void
vmcs_intel_x64_eapis::pass_through_on_cr3_load()
{ exec_ctls1::cr3_load_exiting::disable_if_allowed(verbose); }

void
vmcs_intel_x64_eapis::trap_on_cr8_store()
{ exec_ctls1::cr8_store_exiting::enable(); }

void
vmcs_intel_x64_eapis::pass_through_on_cr8_store()
{ exec_ctls1::cr8_store_exiting::disable(); }

void
vmcs_intel_x64_eapis::trap_on_cr8_load()
{ exec_ctls1::cr8_load_exiting::enable(); }

void
vmcs_intel_x64_eapis::pass_through_on_cr8_load()
{ exec_ctls1::cr8_load_exiting::disable(); }

std::vector<uint64_t>::iterator
vmcs_intel_x64_eapis::trap_list_it(uint64_t gfn_4k)
{
    expects((gfn_4k & (ept::pt::size_bytes - 1)) == 0);
    return std::find(g_trap_list->begin(), g_trap_list->end(), gfn_4k);
}

std::vector<uint64_t>::iterator
vmcs_intel_x64_eapis::split_list_it(uint64_t gfn_2m)
{
    expects((gfn_2m & (ept::pd::size_bytes - 1)) == 0);
    return std::find(g_split_list->begin(), g_split_list->end(), gfn_2m);
}

/*
 * Adapted from extended_apis_example_hook/exit_handler/exit_handler_hook.h
 */
void
vmcs_intel_x64_eapis::trap_gpa(uint64_t gpa)
{
    auto gfn_2m = (gpa & ~(ept::pd::size_bytes - 1));
    auto gfn_4k = (gpa & ~(ept::pt::size_bytes - 1));

    if (trap_list_it(gfn_4k) != g_trap_list->end()) {
        ecr_dbg << "EPT: gpa " << view_as_pointer(gpa)
            << " already configured to trap" << bfendl;
        return;
    }

    if (g_trap_list->size() >= g_trap_list->capacity()) {
        ecr_dbg << "EPT: cannot trap gpa "
            << view_as_pointer(gpa) << bfendl;
        ecr_dbg << ": trap list capacity reached" << bfendl;
        return;
    }

    if (split_list_it(gfn_2m) != g_split_list->end()) {
        auto &&entry = g_ept->gpa_to_epte(gpa);
        entry.trap_on_access();
        g_trap_list->push_back(gfn_4k);
        return;
    }

    if (g_split_list->size() == g_split_list->capacity()) {
        ecr_dbg << "EPT: cannot split 2M -> 4k: capacity reached" << bfendl;
        return;
    }

    g_ept->unmap(gfn_2m);
    g_ept->setup_identity_map_4k(gfn_2m, gfn_2m + ept::pd::size_bytes);
    g_split_list->push_back(gfn_2m);

    auto &&entry = g_ept->gpa_to_epte(gpa);
    entry.trap_on_access();
    g_trap_list->push_back(gfn_4k);
}

void
vmcs_intel_x64_eapis::pass_through_gpa(uint64_t gpa)
{
    auto gfn_4k = (gpa & ~(ept::pt::size_bytes - 1));
    auto &&it = trap_list_it(gfn_4k);

    if ((it = trap_list_it(gfn_4k)) == g_trap_list->end()) {
        ecr_dbg << "EPT: gpa " << view_as_pointer(gpa)
            << " already configured to pass-through" << bfendl;
        return;
    }

    auto &&entry = g_ept->gpa_to_epte(gpa);
    entry.pass_through_access();
    g_trap_list->erase(it);
}
