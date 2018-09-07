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

#include <bfcallonce.h>

#include <bfvmm/vcpu/vcpu_factory.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

bfn::once_flag flag;
ept::mmap g_guest_map;

class vcpu : public eapis::intel_x64::vcpu
{
public:
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        bfn::call_once(flag, [&] {
            ept::identity_map(
                g_guest_map,
                MAX_PHYS_ADDR
            );
        });

        eapis()->enable_vpid();
        eapis()->set_eptp(g_guest_map);

        eapis()->enable_wrcr0_exiting(
            0xFFFFFFFFFFFFFFFF, ::intel_x64::vmcs::guest_cr0::get()
        );

        eapis()->enable_wrcr4_exiting(
            0xFFFFFFFFFFFFFFFF, ::intel_x64::vmcs::guest_cr4::get()
        );

        eapis()->add_handler(
            vmcs_n::exit_reason::basic_exit_reason::xsetbv,
            ::handler_delegate_t::create<vcpu, &vcpu::handle_xsetbv>(this)
        );

        eapis()->wrmsr()->trap_on_all_accesses();
        eapis()->rdmsr()->trap_on_all_accesses();

        eapis()->rdmsr()->pass_through_access(0x0000000000000017);
        eapis()->rdmsr()->pass_through_access(0x0000000000000079);
        eapis()->rdmsr()->pass_through_access(0x000000000000008b);

        eapis()->wrmsr()->pass_through_access(0x0000000000000017);
        eapis()->wrmsr()->pass_through_access(0x0000000000000079);
        eapis()->wrmsr()->pass_through_access(0x000000000000008b);
    }

    bool
    handle_xsetbv(
        gsl::not_null<vmcs_t *> vmcs)
    {
        auto val = 0ULL;

        val |= ((vmcs->save_state()->rax & 0x00000000FFFFFFFF) << 0x00);
        val |= ((vmcs->save_state()->rdx & 0x00000000FFFFFFFF) << 0x20);

        _xsetbv(val);

        return advance(vmcs);
    }

    bool
    wrmsr_handle_efer(
        gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info)
    {
        using namespace vmcs_n::guest_ia32_efer;

        bfignored(vmcs);

        if (vmcs_n::guest_cr0::paging::is_disabled()) {
            lma::disable(info.val);
        }
        else {
            lma::enable(info.val);
        }

        m_ia32_efer_shadow = info.val;

        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_info(0, "wrmsr_handle_efer", msg);
            bfdebug_subnhex(0, "val", info.val, msg);
            bfdebug_subnhex(0, "shadow", m_ia32_efer_shadow, msg);
        });

        return true;
    }

private:

    uint64_t m_ia32_efer_shadow{};
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
