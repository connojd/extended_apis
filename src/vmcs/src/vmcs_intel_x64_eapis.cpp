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

#include <vmcs/root_ept_intel_x64.h>
#include <vmcs/vmcs_intel_x64_eapis.h>

using namespace intel_x64;
using namespace vmcs;

#ifndef MAX_PHYS_ADDR
#define MAX_PHYS_ADDR 0x20000000000
#endif

std::unique_ptr<root_ept_intel_x64> g_root_ept;

vmcs_intel_x64_eapis::vmcs_intel_x64_eapis()
{
    static intel_x64::vmcs::value_type g_vpid = 1;
    m_vpid = g_vpid++;
}

void
vmcs_intel_x64_eapis::write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                                   gsl::not_null<vmcs_intel_x64_state *> guest_state)
{
    vmcs_intel_x64::write_fields(host_state, guest_state);

    // EPT passthrough
    static auto ept_enabled = false;
    if (!ept_enabled) {
        g_root_ept = std::make_unique<root_ept_intel_x64>();
        g_root_ept->setup_identity_map_1g(0, MAX_PHYS_ADDR);
        ept_enabled = true;
    }
    this->enable_ept(g_root_ept->eptp());
    this->enable_vpid();

    // IO passthrough
    this->enable_io_bitmaps();
    this->pass_through_all_io_accesses();

    // MSR passthrough
    this->enable_msr_bitmap();
    msr_list_type list = {
    //    intel_x64::msrs::ia32_debugctl::addr,
    //    x64::msrs::ia32_pat::addr,
    //    intel_x64::msrs::ia32_efer::addr,
    //    intel_x64::msrs::ia32_perf_global_ctrl::addr,
    //    intel_x64::msrs::ia32_sysenter_cs::addr,
    //    intel_x64::msrs::ia32_sysenter_esp::addr,
    //    intel_x64::msrs::ia32_sysenter_eip::addr,
    //    intel_x64::msrs::ia32_fs_base::addr,
    //    intel_x64::msrs::ia32_gs_base::addr
    };
    this->blacklist_rdmsr_access(list);
    this->blacklist_wrmsr_access(list);

    this->disable_cr0_load_hook();
    this->disable_cr3_load_hook();
    this->disable_cr3_store_hook();
    this->disable_cr4_load_hook();
    this->disable_cr8_load_hook();
    this->disable_cr8_store_hook();
    this->disable_event_management();
}
