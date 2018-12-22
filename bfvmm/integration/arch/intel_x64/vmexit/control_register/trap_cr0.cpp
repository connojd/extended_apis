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

#include <bfvmm/vcpu/vcpu_factory.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

uint64_t g_cr0;

bool
test_handler(
    gsl::not_null<vcpu_t *> vcpu, control_register_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    info.val = g_cr0;
    info.shadow = g_cr0;

    return false;
}

void
test_hlt_delegate(bfobject *obj)
{
    bfignored(obj);

    g_cr0 = ::intel_x64::cr0::get();
    ::intel_x64::cr0::set(0);

    if (::intel_x64::cr0::get() == g_cr0) {
        bfdebug_pass(0, "test");
    }
}

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

class vcpu : public eapis::intel_x64::vcpu
{
public:
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        this->add_hlt_delegate(
            hlt_delegate_t::create<test_hlt_delegate>()
        );

        this->add_wrcr0_handler(
            0xFFFFFFFFFFFFFFFF,
            control_register_handler::handler_delegate_t::create<test_handler>()
        );
    }

    ~vcpu() override = default;

public:

    /// @cond

    vcpu(vcpu &&) = delete;
    vcpu &operator=(vcpu &&) = delete;

    vcpu(const vcpu &) = delete;
    vcpu &operator=(const vcpu &) = delete;

    /// @endcond
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
