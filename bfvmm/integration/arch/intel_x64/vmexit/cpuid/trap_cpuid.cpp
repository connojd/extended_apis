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

bool
test_cpuid_handler(
    gsl::not_null<vmcs_t *> vmcs, cpuid_handler::info_t &info)
{
    bfignored(vmcs);

    info.rax = 42;
    info.rbx = 42;
    info.rcx = 42;
    info.rdx = 42;

    return true;
}

void
test_hlt_delegate(bfobject *obj)
{
    bfignored(obj);

    auto ret =
        ::x64::cpuid::get(
            42, 0, 0, 0
        );

    bfdebug_nhex(0, "ret.rax", ret.rax);
    bfdebug_nhex(0, "ret.rbx", ret.rbx);
    bfdebug_nhex(0, "ret.rcx", ret.rcx);
    bfdebug_nhex(0, "ret.rdx", ret.rdx);
}

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

class vcpu : public eapis::intel_x64::vcpu
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        this->add_hlt_delegate(
            hlt_delegate_t::create<test_hlt_delegate>()
        );

        eapis()->add_cpuid_handler(
            42, cpuid_handler::handler_delegate_t::create<test_cpuid_handler>()
        );

        eapis()->cpuid()->enable_log();
    }

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
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
