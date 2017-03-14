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

#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

exit_handler_intel_x64_eapis::exit_handler_intel_x64_eapis() :
    m_monitor_trap_callback(&exit_handler_intel_x64_eapis::unhandled_monitor_trap_callback),
    m_vmcs_eapis(nullptr)
{
}

void
exit_handler_intel_x64_eapis::resume()
{
    m_vmcs_eapis->resume();
}

void
exit_handler_intel_x64_eapis::advance_and_resume()
{
    this->advance_rip();
    m_vmcs_eapis->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit(vmcs::value_type reason)
{
    switch (reason)
    {
        case exit_reason::basic_exit_reason::monitor_trap_flag:
            handle_exit__monitor_trap_flag();
            break;

        case exit_reason::basic_exit_reason::io_instruction:
            handle_exit__io_instruction();
            break;

        case vmcs::exit_reason::basic_exit_reason::rdmsr:
            handle_exit__rdmsr();
            break;

        case vmcs::exit_reason::basic_exit_reason::wrmsr:
            handle_exit__wrmsr();
            break;

        default:
            exit_handler_intel_x64::handle_exit(reason);
            break;
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers(vmcall_registers_t &regs)
{
    switch (regs.r02)
    {
        case eapis_cat__io_instruction:
            handle_vmcall_registers__io_instruction(regs);
            break;

        case eapis_cat__vpid:
            handle_vmcall_registers__vpid(regs);
            break;

        case eapis_cat__msr:
            handle_vmcall_registers__msr(regs);
            break;

        case eapis_cat__rdmsr:
            handle_vmcall_registers__rdmsr(regs);
            break;

        case eapis_cat__wrmsr:
            handle_vmcall_registers__wrmsr(regs);
            break;

        default:
            throw std::runtime_error("unknown vmcall category");
    }
}

void
exit_handler_intel_x64_eapis::trap_on_io_access_callback()
{
    primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__io_instruction()
{
    register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_io_access_callback);

    primary_processor_based_vm_execution_controls::use_io_bitmaps::disable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__io_instruction(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__trap_on_io_access:
            handle_vmcall__trap_on_io_access(gsl::narrow_cast<port_type>(regs.r04));
            break;

        case eapis_fun__trap_on_all_io_accesses:
            handle_vmcall__trap_on_all_io_accesses();
            break;

        case eapis_fun__pass_through_io_access:
            handle_vmcall__pass_through_io_access(gsl::narrow_cast<port_type>(regs.r04));
            break;

        case eapis_fun__pass_through_all_io_accesses:
            handle_vmcall__pass_through_all_io_accesses();
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_io_access(
    port_type port)
{
    m_vmcs_eapis->trap_on_io_access(port);
    vmcall_debug << "trap_on_io_access: " << std::hex << "0x" << port << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_io_accesses()
{
    m_vmcs_eapis->trap_on_all_io_accesses();
    vmcall_debug << "trap_on_all_io_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_io_access(
    port_type port)
{
    m_vmcs_eapis->pass_through_io_access(port);
    vmcall_debug << "pass_through_io_access: " << std::hex << "0x" << port << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_io_accesses()
{
    m_vmcs_eapis->pass_through_all_io_accesses();
    vmcall_debug << "pass_through_all_io_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::clear_monitor_trap()
{
    primary_processor_based_vm_execution_controls::monitor_trap_flag::disable();
    m_monitor_trap_callback = &exit_handler_intel_x64_eapis::unhandled_monitor_trap_callback;
}

void
exit_handler_intel_x64_eapis::unhandled_monitor_trap_callback()
{ throw std::logic_error("unhandled_monitor_trap_callback called!!!"); }

void
exit_handler_intel_x64_eapis::handle_exit__monitor_trap_flag()
{
    auto callback = m_monitor_trap_callback;

    clear_monitor_trap();
    (this->*callback)();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__msr(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__enable_msr_bitmap:
            handle_vmcall__enable_msr_bitmap(true);
            break;

        case eapis_fun__disable_msr_bitmap:
            handle_vmcall__enable_msr_bitmap(false);
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__enable_msr_bitmap(
    bool enabled)
{
    if (enabled)
    {
        m_vmcs_eapis->enable_msr_bitmap();
        vmcall_debug << "enable_msr_bitmap: success" << bfendl;
    }
    else
    {
        m_vmcs_eapis->disable_msr_bitmap();
        vmcall_debug << "disable_msr_bitmap: success" << bfendl;
    }
}

void
exit_handler_intel_x64_eapis::log_rdmsr_access(bool enable)
{ m_rdmsr_access_log_enabled = enable; }

void
exit_handler_intel_x64_eapis::clear_rdmsr_access_log()
{ m_rdmsr_access_log.clear(); }

void
exit_handler_intel_x64_eapis::handle_exit__rdmsr()
{
    if (m_rdmsr_access_log_enabled)
        m_rdmsr_access_log[static_cast<msr_type>(m_state_save->rcx)]++;

    this->handle_rdmsr();
    this->resume();
}

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
    vmcall_debug << "trap_on_rdmsr_access: " << std::hex << "0x" << msr << bfendl;
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
    vmcall_debug << "pass_through_rdmsr_access: " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_rdmsr_accesses()
{
    m_vmcs_eapis->pass_through_all_rdmsr_accesses();
    vmcall_debug << "pass_through_on_all_rdmsr_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__whitelist_rdmsr_access(
    msr_list_type msrs)
{
    m_vmcs_eapis->whitelist_rdmsr_access(msrs);

    vmcall_debug << "whitelist_rdmsr_access: " << bfendl;
    for (auto msr : msrs)
        vmcall_debug << "  - " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__blacklist_rdmsr_access(
    msr_list_type msrs)
{
    m_vmcs_eapis->blacklist_rdmsr_access(msrs);

    vmcall_debug << "blacklist_rdmsr_access: " << bfendl;
    for (auto msr : msrs)
        vmcall_debug << "  - " << std::hex << "0x" << msr << bfendl;
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

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__vpid(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__vpid_on:
            handle_vmcall__enable_vpid(true);
            break;

        case eapis_fun__vpid_off:
            handle_vmcall__enable_vpid(false);
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__enable_vpid(bool enabled)
{
    if (enabled)
    {
        m_vmcs_eapis->enable_vpid();
        vmcall_debug << "enable_vpid: success" << bfendl;
    }
    else
    {
        m_vmcs_eapis->disable_vpid();
        vmcall_debug << "disable_vpid: success" << bfendl;
    }
}

void
exit_handler_intel_x64_eapis::log_wrmsr_access(bool enable)
{ m_wrmsr_access_log_enabled = enable; }

void
exit_handler_intel_x64_eapis::clear_wrmsr_access_log()
{ m_wrmsr_access_log.clear(); }

void
exit_handler_intel_x64_eapis::handle_exit__wrmsr()
{
    if (m_wrmsr_access_log_enabled)
        m_wrmsr_access_log[static_cast<msr_type>(m_state_save->rcx)]++;

    this->handle_wrmsr();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__wrmsr(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__trap_on_wrmsr_access:
            handle_vmcall__trap_on_wrmsr_access(gsl::narrow_cast<msr_type>(regs.r04));
            break;

        case eapis_fun__trap_on_all_wrmsr_accesses:
            handle_vmcall__trap_on_all_wrmsr_accesses();
            break;

        case eapis_fun__pass_through_wrmsr_access:
            handle_vmcall__pass_through_wrmsr_access(gsl::narrow_cast<msr_type>(regs.r04));
            break;

        case eapis_fun__pass_through_all_wrmsr_accesses:
            handle_vmcall__pass_through_all_wrmsr_accesses();
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_wrmsr_access(
    msr_type msr)
{
    m_vmcs_eapis->trap_on_wrmsr_access(msr);
    vmcall_debug << "trap_on_wrmsr_access: " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_wrmsr_accesses()
{
    m_vmcs_eapis->trap_on_all_wrmsr_accesses();
    vmcall_debug << "trap_on_all_wrmsr_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_wrmsr_access(
    msr_type msr)
{
    m_vmcs_eapis->pass_through_wrmsr_access(msr);
    vmcall_debug << "pass_through_wrmsr_access: " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_wrmsr_accesses()
{
    m_vmcs_eapis->pass_through_all_wrmsr_accesses();
    vmcall_debug << "pass_through_on_all_wrmsr_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__whitelist_wrmsr_access(
    msr_list_type msrs)
{
    m_vmcs_eapis->whitelist_wrmsr_access(msrs);

    vmcall_debug << "whitelist_wrmsr_access: " << bfendl;
    for (auto msr : msrs)
        vmcall_debug << "  - " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__blacklist_wrmsr_access(
    msr_list_type msrs)
{
    m_vmcs_eapis->blacklist_wrmsr_access(msrs);

    vmcall_debug << "blacklist_wrmsr_access: " << bfendl;
    for (auto msr : msrs)
        vmcall_debug << "  - " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__log_wrmsr_access(
    bool enabled)
{
    log_wrmsr_access(enabled);
    vmcall_debug << "log_wrmsr_access: " << enabled << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_wrmsr_access_log()
{
    clear_wrmsr_access_log();
    vmcall_debug << "clear_wrmsr_access_log: success" << bfendl;
}
