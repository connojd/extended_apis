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

#include "eapis_vcpu.h"

using namespace eapis::intel_x64;

namespace efi
{

/// EFI vCPU
///
/// This class provides a vCPU for use when booting directly from EFI
///
class vcpu : public eapis::intel_x64::vcpu
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    ///
    vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id},
        m_hve{std::make_unique<eapis::intel_x64::hve>(exit_handler(), vmcs())}
    {
        hve()->enable_wrcr0_exiting(
            0xFFFFFFFFFFFFFFFF, ::intel_x64::vmcs::guest_cr0::get()
        );

        hve()->add_wrcr0_handler(
            control_register::handler_delegate_t::create<vcpu, &vcpu::handle_wrcr0>(this)
        );

        hve()->enable_wrcr4_exiting(
            ::intel_x64::cr4::vmx_enable_bit::mask, ::intel_x64::vmcs::guest_cr4::get()
        );

        hve()->add_wrcr4_handler(
            control_register::handler_delegate_t::create<vcpu, &vcpu::handle_wrcr4>(this)
        );

        exit_handler()->add_handler(
            ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid,
            ::handler_delegate_t::create<vcpu, &vcpu::handle_cpuid>(this)
            );

        exit_handler()->add_handler(
            ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr,
            ::handler_delegate_t::create<vcpu, &vcpu::handle_rdmsr>(this)
            );

        exit_handler()->add_handler(
            ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr,
            ::handler_delegate_t::create<vcpu, &vcpu::handle_wrmsr>(this)
            );

        exit_handler()->add_handler(
            ::intel_x64::vmcs::exit_reason::basic_exit_reason::init_signal,
            ::handler_delegate_t::create<vcpu, &vcpu::handle_init_signal>(this)
            );

        exit_handler()->add_handler(
            ::intel_x64::vmcs::exit_reason::basic_exit_reason::sipi,
            ::handler_delegate_t::create<vcpu, &vcpu::handle_sipi>(this)
            );

        exit_handler()->add_handler(
            ::intel_x64::vmcs::exit_reason::basic_exit_reason::ept_violation,
            ::handler_delegate_t::create<vcpu, &vcpu::handle_ept_violation>(this)
            );

        exit_handler()->add_handler(
            ::intel_x64::vmcs::exit_reason::basic_exit_reason::vmcall,
            ::handler_delegate_t::create<vcpu, &vcpu::handle_vmcall>(this)
            );
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

    /// Called when processor has returned to long mode after
    /// receiving init/sipi
    ///
    /// @expects
    /// @ensures
    ///
    virtual void on_boot()
    { }

private:

    std::unique_ptr<eapis::intel_x64::hve> m_hve;
    std::unique_ptr<eapis::intel_x64::vic> m_vic;

    bool handle_cpuid(gsl::not_null<vmcs_t *> vmcs);
    bool handle_rdmsr(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrmsr(gsl::not_null<vmcs_t *> vmcs);
    bool handle_ept_violation(gsl::not_null<vmcs_t *> vmcs);
    bool handle_vmcall(gsl::not_null<vmcs_t *> vmcs);
    bool handle_init_signal(gsl::not_null<vmcs_t *> vmcs);
    bool handle_sipi(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrcr0(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info);
    bool handle_wrcr4(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info);

};

}
