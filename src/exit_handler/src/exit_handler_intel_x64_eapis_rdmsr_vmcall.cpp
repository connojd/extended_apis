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

#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_vmcall_interface.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__rdmsr(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__trap_on_rdmsr_access:
            handle_vmcall__trap_on_rdmsr_access(gsl::narrow_cast<msr_type>(regs.r04));
            break;

        case eapis_fun__trap_on_all_rdmsr_accesses:
            handle_vmcall__trap_on_all_rdmsr_accesses();
            break;

        case eapis_fun__pass_through_rdmsr_access:
            handle_vmcall__pass_through_rdmsr_access(gsl::narrow_cast<msr_type>(regs.r04));
            break;

        case eapis_fun__pass_through_all_rdmsr_accesses:
            handle_vmcall__pass_through_all_rdmsr_accesses();
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_rdmsr_access(
    msr_type msr)
{
    m_vmcs_eapis->trap_on_rdmsr_access(msr);
    vmcall_debug << "trap_on_rdmsr_access: " << std::hex << std::uppercase << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_rdmsr_accesses()
{
    m_vmcs_eapis->trap_on_all_rdmsr_accesses();
    vmcall_debug << "trap_on_all_rdmsr_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_rdmsr_access(
    msr_type msr)
{
    m_vmcs_eapis->pass_through_rdmsr_access(msr);
    vmcall_debug << "pass_through_rdmsr_access: " << std::hex << std::uppercase << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_rdmsr_accesses()
{
    m_vmcs_eapis->pass_through_all_rdmsr_accesses();
    vmcall_debug << "trap_on_all_io_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__whitelist_rdmsr_access(
    msr_list_type msrs)
{
    m_vmcs_eapis->whitelist_rdmsr_access(msrs);

    vmcall_debug << "whitelist_rdmsr_access: " << bfendl;
    for (auto msr : msrs)
        vmcall_debug << "  - " << std::hex << std::uppercase << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__blacklist_rdmsr_access(
    msr_list_type msrs)
{
    m_vmcs_eapis->blacklist_rdmsr_access(msrs);

    vmcall_debug << "blacklist_rdmsr_access: " << bfendl;
    for (auto msr : msrs)
        vmcall_debug << "  - " << std::hex << std::uppercase << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__log_rdmsr_access(
    bool enabled)
{
    log_rdmsr_access(enabled);
    vmcall_debug << "log_rdmsr_access: " << std::boolalpha << enabled << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_rdmsr_access_log()
{
    clear_rdmsr_access_log();
    vmcall_debug << "clear_rdmsr_access_log: success" << bfendl;
}
