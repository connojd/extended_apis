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
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>

#include <intrinsics/rdrand_x64.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

namespace exit_instr_info = vm_exit_instruction_information;

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

        case vmcs::exit_reason::basic_exit_reason::rdrand:
            handle_exit__rdrand();
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

        case eapis_cat__rdmsr:
            handle_vmcall_registers__rdmsr(regs);
            break;

        case eapis_cat__wrmsr:
            handle_vmcall_registers__wrmsr(regs);
            break;

        case eapis_cat__rdrand:
            handle_vmcall_registers__rdrand(regs);
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
    ecr_dbg << "trap_on_io_access: " << std::hex << "0x" << port << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_io_accesses()
{
    m_vmcs_eapis->trap_on_all_io_accesses();
    ecr_dbg << "trap_on_all_io_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_io_access(
    port_type port)
{
    m_vmcs_eapis->pass_through_io_access(port);
    ecr_dbg << "pass_through_io_access: " << std::hex << "0x" << port << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_io_accesses()
{
    m_vmcs_eapis->pass_through_all_io_accesses();
    ecr_dbg << "pass_through_all_io_accesses: success" << bfendl;
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
exit_handler_intel_x64_eapis::handle_exit__rdmsr()
{
    static bool rdmsr_print = true;

    this->handle_rdmsr();

    if (rdmsr_print) {
        ecr_dbg << "handled rdmsr: " << m_state_save->rcx << bfendl;
        rdmsr_print = false;
    }

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
    ecr_dbg << "trap_on_rdmsr_access: " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_rdmsr_accesses()
{
    m_vmcs_eapis->trap_on_all_rdmsr_accesses();
    ecr_dbg << "trap_on_all_rdmsr_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_rdmsr_access(
    msr_type msr)
{
    m_vmcs_eapis->pass_through_rdmsr_access(msr);
    ecr_dbg << "pass_through_rdmsr_access: " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_rdmsr_accesses()
{
    m_vmcs_eapis->pass_through_all_rdmsr_accesses();
    ecr_dbg << "pass_through_on_all_rdmsr_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_exit__wrmsr()
{
    static bool wrmsr_print = true;

    this->handle_wrmsr();

    if (wrmsr_print) {
        ecr_dbg << "handled wrmsr: " << m_state_save->rcx << bfendl;
        wrmsr_print = false;
    }

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
    ecr_dbg << "trap_on_wrmsr_access: " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_wrmsr_accesses()
{
    m_vmcs_eapis->trap_on_all_wrmsr_accesses();
    ecr_dbg << "trap_on_all_wrmsr_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_wrmsr_access(
    msr_type msr)
{
    m_vmcs_eapis->pass_through_wrmsr_access(msr);
    ecr_dbg << "pass_through_wrmsr_access: " << std::hex << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_wrmsr_accesses()
{
    m_vmcs_eapis->pass_through_all_wrmsr_accesses();
    ecr_dbg << "pass_through_on_all_wrmsr_accesses: success" << bfendl;
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
        ecr_dbg << "enable_vpid: success" << bfendl;
    }
    else
    {
        m_vmcs_eapis->disable_vpid();
        ecr_dbg << "disable_vpid: success" << bfendl;
    }
}

ret_code
exit_handler_intel_x64_eapis::write_gpr(instr_gpr id, uint64_t val,
    uint64_t nbytes)
{
    uint64_t mask = 0xffffffffffffffff;

    switch (nbytes) {
        case 2: break;
        case 1: mask = 0xffffffff; break;
        case 0: mask = 0xffff; break;
        default: bfdebug << "op size = " << nbytes << bfendl; return invl_sz;
    }

    val &= mask;

    switch (id) {
        case rax: m_state_save->rax |= val; break;
        case rcx: m_state_save->rcx |= val; break;
        case rdx: m_state_save->rdx |= val; break;
        case rbx: m_state_save->rbx |= val; break;
        case rsp: m_state_save->rsp |= val; break;
        case rbp: m_state_save->rbp |= val; break;
        case rsi: m_state_save->rsi |= val; break;
        case rdi: m_state_save->rdi |= val; break;
//        case r8: m_state_save->r8 |= val; break; <- no in m_state_save rn
//        case r9: m_state_save->r9 |= val; break;
        case r10: m_state_save->r10 |= val; break;
        case r11: m_state_save->r11 |= val; break;
        case r12: m_state_save->r12 |= val; break;
        case r13: m_state_save->r13 |= val; break;
        case r14: m_state_save->r14 |= val; break;
        case r15: m_state_save->r15 |= val; break;
        default: return invl_gpr;
    }

    return success;
}

void
exit_handler_intel_x64_eapis::handle_exit__rdrand()
{
    instr_gpr dest = static_cast<instr_gpr>
        (exit_instr_info::rdrand::destination_register::get());
    uint64_t size = exit_instr_info::rdrand::operand_size::get();

    int64_t ret = 0;

    ret = (guest_ss_access_rights::dpl::get() > 0) ?
        write_gpr(dest, 0xffffffffffffffff, size) :
        write_gpr(dest, x64::rdrand::get(), size);

    if (invl_sz == ret)
        bferror << "invalid rdrand operand size" << bfendl;

    if (invl_gpr == ret)
        bferror << "invalid rdrand destination register" << bfendl;

    vmcs::guest_rflags::carry_flag::enable();
    vmcs::guest_rflags::overflow_flag::disable();
    vmcs::guest_rflags::sign_flag::disable();
    vmcs::guest_rflags::zero_flag::disable();
    vmcs::guest_rflags::auxiliary_carry_flag::disable();
    vmcs::guest_rflags::parity_flag::disable();

    this->advance_and_resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__rdrand(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__trap_on_rdrand:
            handle_vmcall__trap_on_rdrand();
            break;

        case eapis_fun__pass_through_on_rdrand:
            handle_vmcall__pass_through_on_rdrand();
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_rdrand()
{
    m_vmcs_eapis->trap_on_rdrand();
    ecr_dbg << "trap_on_rdrand: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_on_rdrand()
{
    m_vmcs_eapis->pass_through_on_rdrand();
    ecr_dbg << "pass_through_on_rdrand: success" << bfendl;
}
