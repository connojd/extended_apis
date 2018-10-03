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

#include <hve/arch/intel_x64/vcpu.h>

namespace eapis::intel_x64
{

static bool
handle_cpuid_feature_information(
    gsl::not_null<vmcs_t *> vmcs, cpuid_handler::info_t &info)
{
    bfignored(vmcs);

    // Currently, we do not support nested virtualization. As a result,
    // the EAPIs adds a default handler to disable support for VMXE here.
    //

    info.rcx =
        clear_bit(
            info.rcx, ::intel_x64::cpuid::feature_information::ecx::vmx::from
        );

    return true;
}

cpuid_handler::cpuid_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::cpuid,
        ::handler_delegate_t::create<cpuid_handler, &cpuid_handler::handle>(this)
    );

    this->add_handler(
        ::intel_x64::cpuid::feature_information::addr,
        cpuid_handler::handler_delegate_t::create<handle_cpuid_feature_information>()
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void cpuid_handler::add_handler(
    leaf_t leaf, const handler_delegate_t &d)
{ m_handlers[leaf].push_front(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    const auto &hdlrs =
        m_handlers.find(vmcs->save_state()->rax);

    if (hdlrs != m_handlers.end()) {

        auto [rax, rbx, rcx, rdx] =
            ::x64::cpuid::get(
                gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rax),
                gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rbx),
                gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rcx),
                gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rdx)
            );

        struct info_t info = {
            rax, rbx, rcx, rdx, false, false
        };

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {

                if (!info.ignore_write) {
                    vmcs->save_state()->rax = set_bits(vmcs->save_state()->rax, 0x00000000FFFFFFFFULL, info.rax);
                    vmcs->save_state()->rbx = set_bits(vmcs->save_state()->rbx, 0x00000000FFFFFFFFULL, info.rbx);
                    vmcs->save_state()->rcx = set_bits(vmcs->save_state()->rcx, 0x00000000FFFFFFFFULL, info.rcx);
                    vmcs->save_state()->rdx = set_bits(vmcs->save_state()->rdx, 0x00000000FFFFFFFFULL, info.rdx);
                }

                if (!info.ignore_advance) {
                    return advance(vmcs);
                }

                return true;
            }
        }
    }

    return false;
}

}
