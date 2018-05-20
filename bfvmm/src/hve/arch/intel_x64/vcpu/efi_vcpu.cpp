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

#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/ept/memory_map.h>
#include <hve/arch/intel_x64/ept/helpers.h>
#include <vcpu/arch/intel_x64/efi_vcpu.h>

using namespace eapis::intel_x64;

namespace efi
{

ept::memory_map *g_mmap = nullptr;

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
vcpu::handle_cpuid(gsl::not_null<vmcs_t *> vmcs)
{
    if (vmcs->save_state()->rax == 0xBF01 || vmcs->save_state()->rax == 0xBF00) {
        // bfvmm handles
        return false;
    }

    auto leaf = vmcs->save_state()->rax;
    auto ret =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rax),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rbx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rcx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rdx)
        );

    vmcs->save_state()->rax = ret.rax;
    vmcs->save_state()->rbx = ret.rbx;
    vmcs->save_state()->rdx = ret.rdx;
    if (leaf == ::intel_x64::cpuid::feature_information::addr) {
        uint64_t setter = ret.rcx;
        setter = clear_bit(setter, ::intel_x64::cpuid::feature_information::ecx::xsave::from);
        setter = clear_bit(setter, ::intel_x64::cpuid::feature_information::ecx::osxsave::from);
        setter = clear_bit(setter, ::intel_x64::cpuid::feature_information::ecx::vmx::from);
        vmcs->save_state()->rcx = setter;
        setter = clear_bit(ret.rdx, ::intel_x64::cpuid::feature_information::edx::mtrr::from);
        vmcs->save_state()->rdx = setter;
    }
    else if ((leaf & 0xC0000000) == 0xC0000000) {
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rcx = 0;
        vmcs->save_state()->rdx = 0;
    }
    else if (leaf == 0x0000000A) {
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rcx = 0;
    }
    else {
        vmcs->save_state()->rcx = ret.rcx;
    }

    return advance(vmcs);
}

bool
vcpu::handle_rdmsr(gsl::not_null<vmcs_t *> vmcs)
{
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx);

    switch (msr) {
        case 0x613:
        case 0x619:
            vmcs->save_state()->rax = 0;
            vmcs->save_state()->rdx = 0;
            return advance(vmcs);
    }

    return false;
}

bool
vcpu::handle_wrmsr(gsl::not_null<vmcs_t *> vmcs)
{
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx);
    uint64_t val = ((vmcs->save_state()->rdx) << 0x20) | ((vmcs->save_state()->rax) & 0xFFFFFFFF);

    if (msr == ::intel_x64::msrs::ia32_efer::addr) {
        if (::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::is_disabled()) {
            return false;
        }

        if (get_bit<uint64_t>(val, ::intel_x64::msrs::ia32_efer::lme::from)) {
            uint64_t s_cr0 = 0;
            s_cr0 = ::vmcs_n::guest_cr0::protection_enable::enable(s_cr0);
            s_cr0 = ::vmcs_n::guest_cr0::extension_type::enable(s_cr0);
            s_cr0 = ::vmcs_n::guest_cr0::numeric_error::enable(s_cr0);
            s_cr0 = ::vmcs_n::guest_cr0::write_protect::enable(s_cr0);
            s_cr0 = ::vmcs_n::guest_cr0::not_write_through::enable(s_cr0);
            s_cr0 = ::vmcs_n::guest_cr0::cache_disable::enable(s_cr0);
            s_cr0 = ::vmcs_n::guest_cr0::paging::enable(s_cr0);
            ::vmcs_n::guest_cr0::set(s_cr0);
            ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::enable();
            ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
            ::vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::disable();
            ::vmcs_n::primary_processor_based_vm_execution_controls::monitor_trap_flag::disable();
            val |= ::intel_x64::msrs::ia32_efer::lma::mask;
        }

        ::vmcs_n::guest_ia32_efer::set(val);

        return advance(vmcs);
    }

    return false;
}

bool
vcpu::handle_ept_violation(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);
    bfdebug_info(0, "warning: ept violation");
    ::vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::disable();
    return true;
}

bool
vcpu::handle_wrcr0(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);
    // only need access type 0 but eapis doesn't handle
    // these other access types properly when cr0 is emulated
    auto access_type = ::vmcs_n::exit_qualification::control_register_access::access_type::get();
    if (access_type == 2) {
        info.shadow = ::vmcs_n::guest_cr0::task_switched::disable(info.shadow);
        info.val = ::vmcs_n::guest_cr0::task_switched::disable(info.val);
    }
    else if (access_type == 3) {
        auto cur = set_bits(::vmcs_n::guest_cr0::get(), ::vmcs_n::exit_qualification::control_register_access::source_data::get(), ~0xFFFFULL);
        info.val = set_bits(cur, ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get(), ~0ULL);
        info.shadow = set_bits(info.shadow, ::vmcs_n::exit_qualification::control_register_access::source_data::get(), ~0xFFFFULL);
    }
    else if (access_type == 0) {
        info.shadow = info.val;
        info.val = ::vmcs_n::guest_cr0::extension_type::enable(info.val);
        info.val = ::vmcs_n::guest_cr0::numeric_error::enable(info.val);
    }
    else {
        throw std::runtime_error("handle_wrcr0 invalid access_type " + std::to_string(access_type));
    }

    return true;
}

bool
vcpu::handle_wrcr4(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);
    info.shadow = info.val;
    info.val = set_bits<::vmcs_n::value_type>(info.val, ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get(), ~0ULL);
    return true;
}

bool
vcpu::handle_vmcall(gsl::not_null<vmcs_t *> vmcs)
{
    uint8_t core = thread_context_cpuid();
    uint16_t bf = 0xFB00;
    vmcs->save_state()->rax = static_cast<uint64_t>(bf | core);
    return advance(vmcs);
}

bool
vcpu::handle_init_signal(
    gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);
    ::vmcs_n::guest_activity_state::set(::vmcs_n::guest_activity_state::wait_for_sipi);
    return true;
}

bool
vcpu::handle_sipi(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);
    if (g_mmap == nullptr) {
        g_mmap = new ept::memory_map();
    }
    ept::identity_map_2m(*g_mmap, 0, ept::epte::memory_attr::wb_pt);
    ::vmcs_n::ept_pointer::set(ept::eptp(*g_mmap));
    ::vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::enable();

    ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::disable();

    ::vmcs_n::value_type s_cr0 = 0;
    ::vmcs_n::value_type s_cr4 = 0;
    s_cr0 = ::vmcs_n::guest_cr0::extension_type::enable(s_cr0);
    s_cr0 = ::vmcs_n::guest_cr0::numeric_error::enable(s_cr0);
    s_cr0 = ::vmcs_n::guest_cr0::not_write_through::enable(s_cr0);
    s_cr0 = ::vmcs_n::guest_cr0::cache_disable::enable(s_cr0);
    s_cr4 = ::vmcs_n::guest_cr4::vmx_enable_bit::enable(s_cr4);
    ::vmcs_n::guest_cr0::set(s_cr0);
    ::vmcs_n::guest_cr4::set(s_cr4);
    ::vmcs_n::guest_cr3::set(0);

    ::intel_x64::cr2::set(0);
    ::intel_x64::cr8::set(0);

    ::vmcs_n::value_type s_ds_ar = 0;
    s_ds_ar = ::vmcs_n::guest_ds_access_rights::type::set(s_ds_ar, 0x3);
    s_ds_ar = ::vmcs_n::guest_ds_access_rights::s::enable(s_ds_ar);
    s_ds_ar = ::vmcs_n::guest_ds_access_rights::present::enable(s_ds_ar);
    ::vmcs_n::guest_ds_selector::set(0);
    ::vmcs_n::guest_ds_base::set(0);
    ::vmcs_n::guest_ds_limit::set(0xFFFF);
    ::vmcs_n::guest_ds_access_rights::set(s_ds_ar);

    ::vmcs_n::value_type s_es_ar = 0;
    s_es_ar = ::vmcs_n::guest_es_access_rights::type::set(s_es_ar, 0x3);
    s_es_ar = ::vmcs_n::guest_es_access_rights::s::enable(s_es_ar);
    s_es_ar = ::vmcs_n::guest_es_access_rights::present::enable(s_es_ar);
    ::vmcs_n::guest_es_selector::set(0);
    ::vmcs_n::guest_es_base::set(0);
    ::vmcs_n::guest_es_limit::set(0xFFFF);
    ::vmcs_n::guest_es_access_rights::set(s_es_ar);

    ::vmcs_n::value_type s_fs_ar = 0;
    s_fs_ar = ::vmcs_n::guest_fs_access_rights::type::set(s_fs_ar, 0x3);
    s_fs_ar = ::vmcs_n::guest_fs_access_rights::s::enable(s_fs_ar);
    s_fs_ar = ::vmcs_n::guest_fs_access_rights::present::enable(s_fs_ar);
    ::vmcs_n::guest_fs_selector::set(0);
    ::vmcs_n::guest_fs_base::set(0);
    ::vmcs_n::guest_fs_limit::set(0xFFFF);
    ::vmcs_n::guest_fs_access_rights::set(s_fs_ar);

    ::vmcs_n::value_type s_gs_ar = 0;
    s_gs_ar = ::vmcs_n::guest_gs_access_rights::type::set(s_gs_ar, 0x3);
    s_gs_ar = ::vmcs_n::guest_gs_access_rights::s::enable(s_gs_ar);
    s_gs_ar = ::vmcs_n::guest_gs_access_rights::present::enable(s_gs_ar);
    ::vmcs_n::guest_gs_selector::set(0);
    ::vmcs_n::guest_gs_base::set(0);
    ::vmcs_n::guest_gs_limit::set(0xFFFF);
    ::vmcs_n::guest_gs_access_rights::set(s_gs_ar);

    ::vmcs_n::value_type s_ss_ar = 0;
    s_ss_ar = ::vmcs_n::guest_ss_access_rights::type::set(s_ss_ar, 0x3);
    s_ss_ar = ::vmcs_n::guest_ss_access_rights::s::enable(s_ss_ar);
    s_ss_ar = ::vmcs_n::guest_ss_access_rights::present::enable(s_ss_ar);
    ::vmcs_n::guest_ss_selector::set(0);
    ::vmcs_n::guest_ss_base::set(0);
    ::vmcs_n::guest_ss_limit::set(0xFFFF);
    ::vmcs_n::guest_ss_access_rights::set(s_ss_ar);

    ::vmcs_n::value_type s_cs_ar = 0;
    s_cs_ar = ::vmcs_n::guest_cs_access_rights::type::set(s_cs_ar, 0xB);
    s_cs_ar = ::vmcs_n::guest_cs_access_rights::s::enable(s_cs_ar);
    s_cs_ar = ::vmcs_n::guest_cs_access_rights::present::enable(s_cs_ar);
    auto vector_segment = ::vmcs_n::exit_qualification::sipi::vector::get() << 8;
    ::vmcs_n::guest_cs_selector::set(vector_segment);
    ::vmcs_n::guest_cs_base::set(vector_segment << 4);
    ::vmcs_n::guest_cs_limit::set(0xFFFF);
    ::vmcs_n::guest_cs_access_rights::set(s_cs_ar);

    ::vmcs_n::value_type s_tr_ar = 0;
    s_tr_ar = ::vmcs_n::guest_tr_access_rights::type::set(s_tr_ar, 0xB);
    s_tr_ar = ::vmcs_n::guest_tr_access_rights::present::enable(s_tr_ar);
    ::vmcs_n::guest_tr_selector::set(0);
    ::vmcs_n::guest_tr_base::set(0);
    ::vmcs_n::guest_tr_limit::set(0xFFFF);
    ::vmcs_n::guest_tr_access_rights::set(s_tr_ar);

    ::vmcs_n::value_type s_ldtr_ar = 0;
    s_ldtr_ar = ::vmcs_n::guest_ldtr_access_rights::type::set(s_ldtr_ar, 0x2);
    s_ldtr_ar = ::vmcs_n::guest_ldtr_access_rights::present::enable(s_ldtr_ar);
    ::vmcs_n::guest_ldtr_selector::set(0);
    ::vmcs_n::guest_ldtr_base::set(0);
    ::vmcs_n::guest_ldtr_limit::set(0xFFFF);
    ::vmcs_n::guest_ldtr_access_rights::set(s_ldtr_ar);

    ::vmcs_n::guest_gdtr_base::set(0);
    ::vmcs_n::guest_gdtr_limit::set(0xFFFF);

    ::vmcs_n::guest_idtr_base::set(0);
    ::vmcs_n::guest_idtr_limit::set(0xFFFF);

    vmcs->save_state()->rax = 0;
    vmcs->save_state()->rbx = 0;
    vmcs->save_state()->rcx = 0;
    vmcs->save_state()->rdx = 0xF00;
    vmcs->save_state()->rdi = 0;
    vmcs->save_state()->rsi = 0;
    vmcs->save_state()->rbp = 0;
    vmcs->save_state()->rsp = 0;
    vmcs->save_state()->rip = 0;

    ::vmcs_n::guest_rflags::set(0x2);
    ::vmcs_n::guest_ia32_efer::set(0);

    ::vmcs_n::guest_activity_state::set(::vmcs_n::guest_activity_state::active);

    return true;
}

}
