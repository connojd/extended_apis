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
#include <eapis/vcpu/arch/intel_x64/vcpu.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
test_handler(
    gsl::not_null<vmcs_t *> vmcs, crs::info_t &info)
{
    bfignored(vmcs);

    info.shadow = info.val;
    info.val |= ::intel_x64::cr4::vmx_enable_bit::mask;

    return true;
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
    vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        this->enable_cr_trapping();

        if (!ndebug) {
            crs()->enable_log();
        }

        if (!ndebug) {
            crs()->enable_log();
        }

        crs()->enable_wrcr4_trapping(
            0xFFFFFFFFFFFFFFFF,
            ::intel_x64::vmcs::guest_cr4::get()
        );

        crs()->add_wrcr4_handler(
            crs::wrcr4_handler_delegate_t::create<test_handler>()
        );
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;
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
