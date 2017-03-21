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
#include <vmcs/vmcs_intel_x64_64bit_read_only_data_fields.h>
#include <vmcs/ept_entry_intel_x64.h>
#include <vmcs/root_ept_intel_x64.h>

#include <intrinsics/rdrand_x64.h>
#include <intrinsics/cache_x64.h>

#include <mutex>

#ifdef ECR_DEBUG
#define verbose true
#else
#define verbose false
#endif

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

namespace exit_instr_info = vm_exit_instruction_information;
namespace exec_ctls1 = primary_processor_based_vm_execution_controls;
namespace exec_ctls2 = secondary_processor_based_vm_execution_controls;

extern std::unique_ptr<root_ept_intel_x64> g_ept;
extern std::unique_ptr<std::vector<uint64_t>> g_trap_list;
extern std::mutex g_ept_mtx;

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

        case vmcs::exit_reason::basic_exit_reason::rdseed:
            handle_exit__rdseed();
            break;

        case vmcs::exit_reason::basic_exit_reason::wbinvd:
            handle_exit__wbinvd();
            break;

        case vmcs::exit_reason::basic_exit_reason::rdpmc:
            handle_exit__rdpmc();
            break;

        case vmcs::exit_reason::basic_exit_reason::rdtsc:
        case vmcs::exit_reason::basic_exit_reason::rdtscp:
            handle_exit__rdtsc();
            break;

        case vmcs::exit_reason::basic_exit_reason::invlpg:
        case vmcs::exit_reason::basic_exit_reason::invpcid:
            handle_exit__invlpg();
            break;

        case vmcs::exit_reason::basic_exit_reason::access_to_gdtr_or_idtr:
        case vmcs::exit_reason::basic_exit_reason::access_to_ldtr_or_tr:
            handle_exit__desc_table();
            break;

        case vmcs::exit_reason::basic_exit_reason::control_register_accesses:
            handle_exit__ctl_reg_access();
            break;

        case vmcs::exit_reason::basic_exit_reason::ept_violation:
            handle_exit__ept_violation();
            break;

        case vmcs::exit_reason::basic_exit_reason::mov_dr:
            handle_exit__mov_dr();
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

        case eapis_cat__rdseed:
            handle_vmcall_registers__rdseed(regs);
            break;

        case eapis_cat__wbinvd:
            handle_vmcall_registers__wbinvd(regs);
            break;

        case eapis_cat__rdpmc:
            handle_vmcall_registers__rdpmc(regs);
            break;

        case eapis_cat__rdtsc:
            handle_vmcall_registers__rdtsc(regs);
            break;

        case eapis_cat__invlpg:
            handle_vmcall_registers__invlpg(regs);
            break;

        case eapis_cat__desc_table:
            handle_vmcall_registers__desc_table(regs);
            break;

        case eapis_cat__cr3_store:
            handle_vmcall_registers__cr3_store(regs);
            break;

        case eapis_cat__cr3_load:
            handle_vmcall_registers__cr3_load(regs);
            break;

        case eapis_cat__cr8_store:
            handle_vmcall_registers__cr8_store(regs);
            break;

        case eapis_cat__cr8_load:
            handle_vmcall_registers__cr8_load(regs);
            break;

        case eapis_cat__ept:
            handle_vmcall_registers__ept(regs);
            break;

        case eapis_cat__mov_dr:
            handle_vmcall_registers__mov_dr(regs);
            break;

        default:
            throw std::runtime_error("unknown vmcall category");
    }
}

void
exit_handler_intel_x64_eapis::trap_on_io_access_callback()
{
    exec_ctls1::use_io_bitmaps::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__io_instruction()
{
    register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_io_access_callback);

    exec_ctls1::use_io_bitmaps::disable();
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
    exec_ctls1::monitor_trap_flag::disable();
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
//        case r8: m_state_save->r8 |= val; break; <- not in m_state_save rn
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

void
exit_handler_intel_x64_eapis::handle_exit__rdseed()
{
    instr_gpr dest = static_cast<instr_gpr>
        (exit_instr_info::rdseed::destination_register::get());
    uint64_t size = exit_instr_info::rdseed::operand_size::get();

    int64_t ret = 0;

    ret = (guest_ss_access_rights::dpl::get() > 0) ?
        write_gpr(dest, 0xbeefcafebeefcafe, size) :
        write_gpr(dest, x64::rdseed::get(), size);

    if (invl_sz == ret)
        bferror << "invalid rdseed operand size" << bfendl;

    if (invl_gpr == ret)
        bferror << "invalid rdseed destination register" << bfendl;

    vmcs::guest_rflags::carry_flag::enable();
    vmcs::guest_rflags::overflow_flag::disable();
    vmcs::guest_rflags::sign_flag::disable();
    vmcs::guest_rflags::zero_flag::disable();
    vmcs::guest_rflags::auxiliary_carry_flag::disable();
    vmcs::guest_rflags::parity_flag::disable();

    this->advance_and_resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__rdseed(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_rdseed:
            m_vmcs_eapis->trap_on_rdseed();
            ecr_dbg << "trap_on_rdseed: success" << bfendl;
            break;

        case eapis_fun__pass_through_on_rdseed:
            m_vmcs_eapis->pass_through_on_rdseed();
            ecr_dbg << "pass_through_on_rdseed: success" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_exit__wbinvd()
{
    x64::cache::wbinvd();
    this->advance_and_resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__wbinvd(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_wbinvd:
            m_vmcs_eapis->trap_on_wbinvd();
            ecr_dbg << "trap_on_wbinvd: success" << bfendl;
            break;

        case eapis_fun__pass_through_on_wbinvd:
            m_vmcs_eapis->pass_through_on_wbinvd();
            ecr_dbg << "pass_through_on_wbinvd: success" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::trap_on_rdpmc_callback()
{
    exec_ctls1::rdpmc_exiting::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__rdpmc()
{
    static bool rdpmc_print = true;

    register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_rdpmc_callback);
    exec_ctls1::rdpmc_exiting::disable();

    if (rdpmc_print) {
        ecr_dbg << "handling rdpmc: " << std::hex << "0x"
            << m_state_save->rcx << bfendl;
        rdpmc_print = false;
    }

    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__rdpmc(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_rdpmc:
            m_vmcs_eapis->trap_on_rdpmc();
            ecr_dbg << "trap_on_rdpmc: success" << bfendl;
            break;

        case eapis_fun__pass_through_on_rdpmc:
            m_vmcs_eapis->pass_through_on_rdpmc();
            ecr_dbg << "pass_through_on_rdpmc: success" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::trap_on_rdtsc_callback()
{
    exec_ctls1::rdtsc_exiting::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__rdtsc()
{
    static bool rdtsc_print = true;

    register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_rdtsc_callback);
    exec_ctls1::rdtsc_exiting::disable();

    if (rdtsc_print) {
        auto reason = exit_reason::basic_exit_reason::get();

        if (reason == exit_reason::basic_exit_reason::rdtsc) {
            ecr_dbg << "handling RDTSC" << bfendl;
        } else {
            ecr_dbg << "handling RDTSCP" << bfendl;
        }

        rdtsc_print = false;
    }

    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__rdtsc(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_rdtsc:
            m_vmcs_eapis->trap_on_rdtsc();
            ecr_dbg << "trapping on RDTSC & RDTSCP" << bfendl;
            break;

        case eapis_fun__pass_through_on_rdtsc:
            m_vmcs_eapis->pass_through_on_rdtsc();
            ecr_dbg << "passing through on RDTSC & RDTSCP" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::trap_on_invlpg_callback()
{
    exec_ctls1::invlpg_exiting::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__invlpg()
{
    static bool invlpg_print = true;

    register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_invlpg_callback);
    exec_ctls1::invlpg_exiting::disable();

    if (invlpg_print) {

        auto reason = exit_reason::basic_exit_reason::get();
        if (reason == exit_reason::basic_exit_reason::invlpg) {
            ecr_dbg << "handling INVLPG" << bfendl;
        } else {
            ecr_dbg << "handling INVPCID" << bfendl;
        }

        invlpg_print = false;
    }

    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__invlpg(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_invlpg:
            m_vmcs_eapis->trap_on_invlpg();
            ecr_dbg << "trapping on INVLPG & INVPCID" << bfendl;
            break;

        case eapis_fun__pass_through_on_invlpg:
            m_vmcs_eapis->pass_through_on_invlpg();
            ecr_dbg << "passing through on INVLPG & INVPCID" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::trap_on_desc_table_callback()
{
    exec_ctls2::descriptor_table_exiting::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__desc_table()
{
    static bool dt_print = true;

    register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_desc_table_callback);
    exec_ctls2::descriptor_table_exiting::disable();

    if (dt_print) {

        auto reason = exit_reason::basic_exit_reason::get();
        if (reason == exit_reason::basic_exit_reason::access_to_gdtr_or_idtr) {
            ecr_dbg << "handling access to GDTR or IDTR" << bfendl;
        } else {
            ecr_dbg << "handling access to LDTR or TR"  << bfendl;
        }

        dt_print = false;
    }

    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__desc_table(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_desc_table:
            m_vmcs_eapis->trap_on_desc_table();
            ecr_dbg << "trapping on descriptor-table register access" << bfendl;
            break;

        case eapis_fun__pass_through_on_desc_table:
            m_vmcs_eapis->pass_through_on_desc_table();
            ecr_dbg << "passing through descriptor-table register access" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::trap_on_cr3_store_callback()
{
    exec_ctls1::cr3_store_exiting::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::trap_on_cr3_load_callback()
{
    exec_ctls1::cr3_load_exiting::enable();
    cr3_target_count::set(0U);
    this->resume();
}

void
exit_handler_intel_x64_eapis::trap_on_cr8_store_callback()
{
    exec_ctls1::cr8_store_exiting::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::trap_on_cr8_load_callback()
{
    exec_ctls1::cr8_load_exiting::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__cr3_access(uint64_t type)
{
    using namespace exit_qualification::control_register_access;

    if (type == access_type::mov_from_cr) {
        register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_cr3_store_callback);
        exec_ctls1::cr3_store_exiting::disable_if_allowed(verbose);

        static bool cr3_st_print = true;
        if (cr3_st_print) {
            ecr_dbg << "handling MOV from CR3" << bfendl;
            cr3_st_print = false;
        }
    } else if (type == access_type::mov_to_cr) {
        register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_cr3_load_callback);
        exec_ctls1::cr3_load_exiting::disable_if_allowed(verbose);

        static bool cr3_ld_print = true;
        if (cr3_ld_print) {
            ecr_dbg << "handling MOV to CR3" << bfendl;
            cr3_ld_print = false;
        }
    } else {
        bferror << "invalid MOV control register type" << bfendl;
    }
}

void
exit_handler_intel_x64_eapis::handle_exit__cr8_access(uint64_t type)
{
    using namespace exit_qualification::control_register_access;

    if (type == access_type::mov_from_cr) {
        register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_cr8_store_callback);
        exec_ctls1::cr8_store_exiting::disable();

        static bool cr8_st_print = true;
        if (cr8_st_print) {
            ecr_dbg << "handling MOV from CR8" << bfendl;
            cr8_st_print = false;
        }
    } else if (type == access_type::mov_to_cr) {
        register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_cr8_load_callback);
        exec_ctls1::cr8_load_exiting::disable();

        static bool cr8_ld_print = true;
        if (cr8_ld_print) {
            ecr_dbg << "handling MOV to CR8" << bfendl;
            cr8_ld_print = false;
        }
    } else {
        bferror << "invalid MOV control register type" << bfendl;
    }
}

void
exit_handler_intel_x64_eapis::handle_exit__ctl_reg_access()
{
    using namespace exit_qualification::control_register_access;

    auto cr = control_register_number::get();
    auto type = access_type::get();

    switch (cr) {
        case 3: handle_exit__cr3_access(type); break;
	case 8: handle_exit__cr8_access(type); break;

        default:
            bferror << "unimplemented control register access" << bfendl;
            break;
    }

    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__cr3_store(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_cr3_store:
            m_vmcs_eapis->trap_on_cr3_store();
            ecr_dbg << "trapping on MOV from CR3" << bfendl;
            break;

        case eapis_fun__pass_through_on_cr3_store:
            m_vmcs_eapis->pass_through_on_cr3_store();
            ecr_dbg << "passing through on MOV from CR3" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__cr3_load(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_cr3_load:
            m_vmcs_eapis->trap_on_cr3_load();
            ecr_dbg << "trapping on MOV to CR3" << bfendl;
            break;

        case eapis_fun__pass_through_on_cr3_load:
            m_vmcs_eapis->pass_through_on_cr3_load();
            ecr_dbg << "passing through on MOV to CR3" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__cr8_store(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_cr8_store:
            m_vmcs_eapis->trap_on_cr8_store();
            ecr_dbg << "trapping on MOV from CR8" << bfendl;
            break;

        case eapis_fun__pass_through_on_cr8_store:
            m_vmcs_eapis->pass_through_on_cr8_store();
            ecr_dbg << "passing through on MOV from CR8" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__cr8_load(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_cr8_load:
            m_vmcs_eapis->trap_on_cr8_load();
            ecr_dbg << "trapping on MOV to CR8" << bfendl;
            break;

        case eapis_fun__pass_through_on_cr8_load:
            m_vmcs_eapis->pass_through_on_cr8_load();
            ecr_dbg << "passing through on MOV to CR8" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_exit__ept_violation()
{
    auto gva = guest_linear_address::get();
    auto gpa = guest_physical_address::get();
    auto gfn = (gpa & ~(ept::pt::size_bytes - 1));

    std::unique_lock<std::mutex> lck(g_ept_mtx);
    auto it = m_vmcs_eapis->trap_list_it(gfn);

    if (it == g_trap_list->end()) {
        bfwarning << "EPT: trapping has not been configured for" << bfendl;
        bfwarning << "     gva = " << view_as_pointer(gva) << bfendl;
        bfwarning << "     gpa = " << view_as_pointer(gpa) << bfendl;
        bfwarning << "     phys mem size = "
            << view_as_pointer(PHYS_MEM_SZ) << bfendl;
    }

    ecr_dbg << "EPT: handling ept violation for\n"
        << "            gva = " << view_as_pointer(gva) << '\n'
        << "            gpa = " << view_as_pointer(gpa) << bfendl;

    m_vmcs_eapis->pass_through_gpa(gpa);
    lck.unlock();

    m_vmcs_eapis->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__ept(
    vmcall_registers_t &regs)
{
    std::lock_guard<std::mutex> lg(g_ept_mtx);

    switch (regs.r03) {
        case eapis_fun__ept_on:
            m_vmcs_eapis->enable_ept();
            ecr_dbg << "EPT: enabled" << bfendl;
            break;

        case eapis_fun__ept_off:
            m_vmcs_eapis->disable_ept();
            ecr_dbg << "EPT: disabled" << bfendl;
            break;

        case eapis_fun__trap_on_gpa:
            m_vmcs_eapis->trap_gpa(regs.r04);
            break;

        case eapis_fun__pass_through_on_gpa:
            m_vmcs_eapis->pass_through_gpa(regs.r04);
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::trap_on_mov_dr_callback()
{
    exec_ctls1::mov_dr_exiting::enable();
    m_vmcs_eapis->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__mov_dr()
{
    static bool dr_print = true;

    if (dr_print) {
        ecr_dbg << "handling MOV DR" << bfendl;
        dr_print = false;
    }

    register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_mov_dr_callback);
    exec_ctls1::mov_dr_exiting::disable();
    m_vmcs_eapis->resume();
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__mov_dr(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_mov_dr:
            m_vmcs_eapis->trap_on_mov_dr();
            ecr_dbg << "Configured trap on MOV DR" << bfendl;
            break;

        case eapis_fun__pass_through_on_mov_dr:
            m_vmcs_eapis->pass_through_on_mov_dr();
            ecr_dbg << "Configured pass-through on MOV DR" << bfendl;
            break;

        default:
            throw std::runtime_error("unknown vmcall mov dr function");
    }
}











