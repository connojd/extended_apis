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

#include <hve/arch/intel_x64/apis.h>

namespace eapis
{
namespace intel_x64
{

apis::apis(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
    gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler
) :
    m_vmcs{vmcs},
    m_exit_handler{exit_handler}
{
    using namespace vmcs_n::secondary_processor_based_vm_execution_controls;
    unrestricted_guest::enable();

    m_init_signal_handler = std::make_unique<init_signal_handler>(this);
    m_sipi_signal_handler = std::make_unique<sipi_signal_handler>(this);
}

//==========================================================================
// MISC
//==========================================================================

//--------------------------------------------------------------------------
// EPT
//--------------------------------------------------------------------------

gsl::not_null<ept_handler *>
apis::ept()
{ return m_ept_handler.get(); }

void
apis::set_eptp(ept::mmap &map)
{
    if (!m_ept_handler) {
        m_ept_handler = std::make_unique<ept_handler>();
    }

    m_ept_handler->set_eptp(&map);
}

void
apis::disable_ept()
{
    if (m_ept_handler) {
        m_ept_handler->set_eptp(nullptr);
    }
}

//--------------------------------------------------------------------------
// VPID
//--------------------------------------------------------------------------

gsl::not_null<vpid_handler *>
apis::vpid()
{ return m_vpid_handler.get(); }

void
apis::enable_vpid()
{
    if (!m_vpid_handler) {
        m_vpid_handler = std::make_unique<vpid_handler>();
    }

    m_vpid_handler->enable();
}

void
apis::disable_vpid()
{
    if (m_vpid_handler) {
        m_vpid_handler->disable();
    }
}

//==========================================================================
// VMExit
//==========================================================================

//--------------------------------------------------------------------------
// Control Register
//--------------------------------------------------------------------------

gsl::not_null<control_register_handler *>
apis::control_register()
{ return m_control_register_handler.get(); }

void
apis::enable_wrcr0_exiting(
    vmcs_n::value_type mask, vmcs_n::value_type shadow)
{
    check_crall();
    m_control_register_handler->enable_wrcr0_exiting(mask, shadow);
}

void
apis::enable_wrcr4_exiting(
    vmcs_n::value_type mask, vmcs_n::value_type shadow)
{
    check_crall();
    m_control_register_handler->enable_wrcr4_exiting(mask, shadow);
}

void
apis::add_wrcr0_handler(
    const control_register_handler::handler_delegate_t &d)
{
    check_crall();
    m_control_register_handler->add_wrcr0_handler(std::move(d));
}

void
apis::add_rdcr3_handler(
    const control_register_handler::handler_delegate_t &d)
{
    check_rdcr3();
    m_control_register_handler->add_rdcr3_handler(std::move(d));
}

void
apis::add_wrcr3_handler(
    const control_register_handler::handler_delegate_t &d)
{
    check_wrcr3();
    m_control_register_handler->add_wrcr3_handler(std::move(d));
}

void
apis::add_wrcr4_handler(
    const control_register_handler::handler_delegate_t &d)
{
    check_crall();
    m_control_register_handler->add_wrcr4_handler(std::move(d));
}

//--------------------------------------------------------------------------
// CPUID
//--------------------------------------------------------------------------

gsl::not_null<cpuid_handler *>
apis::cpuid()
{ return m_cpuid_handler.get(); }

void
apis::add_cpuid_handler(
    cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d)
{
    if (!m_cpuid_handler) {
        m_cpuid_handler = std::make_unique<cpuid_handler>(this);
    }

    m_cpuid_handler->add_handler(leaf, std::move(d));
}

//--------------------------------------------------------------------------
// EPT Misconfiguration
//--------------------------------------------------------------------------

gsl::not_null<ept_misconfiguration_handler *>
apis::ept_misconfiguration()
{ return m_ept_misconfiguration_handler.get(); }

void
apis::add_ept_misconfiguration_handler(
    const ept_misconfiguration_handler::handler_delegate_t &d)
{
    if (!m_ept_misconfiguration_handler) {
        m_ept_misconfiguration_handler = std::make_unique<ept_misconfiguration_handler>(this);
    }

    m_ept_misconfiguration_handler->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// EPT Violation
//--------------------------------------------------------------------------

gsl::not_null<ept_violation_handler *>
apis::ept_violation()
{ return m_ept_violation_handler.get(); }

void
apis::add_ept_read_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{
    if (!m_ept_violation_handler) {
        m_ept_violation_handler = std::make_unique<ept_violation_handler>(this);
    }

    m_ept_violation_handler->add_read_handler(std::move(d));
}

void
apis::add_ept_write_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{
    if (!m_ept_violation_handler) {
        m_ept_violation_handler = std::make_unique<ept_violation_handler>(this);
    }

    m_ept_violation_handler->add_write_handler(std::move(d));
}

void
apis::add_ept_execute_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{
    if (!m_ept_violation_handler) {
        m_ept_violation_handler = std::make_unique<ept_violation_handler>(this);
    }

    m_ept_violation_handler->add_execute_handler(std::move(d));
}

//--------------------------------------------------------------------------
// External Interrupt
//--------------------------------------------------------------------------

gsl::not_null<external_interrupt_handler *>
apis::external_interrupt()
{ return m_external_interrupt_handler.get(); }

void
apis::add_external_interrupt_handler(
    vmcs_n::value_type vector, const external_interrupt_handler::handler_delegate_t &d)
{
    if (!m_external_interrupt_handler) {
        m_external_interrupt_handler = std::make_unique<external_interrupt_handler>(this);
    }

    m_external_interrupt_handler->add_handler(vector, std::move(d));
}

//--------------------------------------------------------------------------
// Interrupt Window
//--------------------------------------------------------------------------

gsl::not_null<interrupt_window_handler *>
apis::interrupt_window()
{ return m_interrupt_window_handler.get(); }

void
apis::add_interrupt_window_handler(
    const interrupt_window_handler::handler_delegate_t &d)
{
    if (!m_interrupt_window_handler) {
        m_interrupt_window_handler =
            std::make_unique<interrupt_window_handler>(this);
    }

    m_interrupt_window_handler->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// IO Instruction
//--------------------------------------------------------------------------

gsl::not_null<io_instruction_handler *>
apis::io_instruction()
{ return m_io_instruction_handler.get(); }

void
apis::add_io_instruction_handler(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    check_io_bitmaps();

    if (!m_io_instruction_handler) {
        m_io_instruction_handler = std::make_unique<io_instruction_handler>(this);
    }

    m_io_instruction_handler->add_handler(port, std::move(in_d), std::move(out_d));
}

//--------------------------------------------------------------------------
// Monitor Trap
//--------------------------------------------------------------------------

gsl::not_null<monitor_trap_handler *>
apis::monitor_trap()
{ return m_monitor_trap_handler.get(); }

void
apis::add_monitor_trap_handler(
    const monitor_trap_handler::handler_delegate_t &d)
{
    if (!m_monitor_trap_handler) {
        m_monitor_trap_handler = std::make_unique<monitor_trap_handler>(this);
    }

    m_monitor_trap_handler->add_handler(std::move(d));
}

void
apis::enable_monitor_trap_flag()
{
    if (!m_monitor_trap_handler) {
        m_monitor_trap_handler = std::make_unique<monitor_trap_handler>(this);
    }

    m_monitor_trap_handler->enable();
}

//--------------------------------------------------------------------------
// Move DR
//--------------------------------------------------------------------------

gsl::not_null<mov_dr_handler *>
apis::mov_dr()
{ return m_mov_dr_handler.get(); }

void
apis::add_mov_dr_handler(
    const mov_dr_handler::handler_delegate_t &d)
{
    if (!m_mov_dr_handler) {
        m_mov_dr_handler = std::make_unique<mov_dr_handler>(this);
    }

    m_mov_dr_handler->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// Read MSR
//--------------------------------------------------------------------------

gsl::not_null<rdmsr_handler *>
apis::rdmsr()
{ return m_rdmsr_handler.get(); }

void
apis::pass_through_all_rdmsr_handler_accesses()
{ check_rdmsr_handler(); }

void
apis::add_rdmsr_handler(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    check_rdmsr_handler();
    m_rdmsr_handler->add_handler(msr, std::move(d));
}

//--------------------------------------------------------------------------
// Write MSR
//--------------------------------------------------------------------------

gsl::not_null<wrmsr_handler *>
apis::wrmsr()
{ return m_wrmsr_handler.get(); }

void
apis::pass_through_all_wrmsr_handler_accesses()
{ check_wrmsr_handler(); }

void
apis::add_wrmsr_handler(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    check_wrmsr_handler();
    m_wrmsr_handler->add_handler(msr, std::move(d));
}

//==========================================================================
// Bitmaps
//==========================================================================

gsl::span<uint8_t>
apis::msr_bitmap()
{ return gsl::make_span(m_msr_bitmap.get(), ::x64::pt::page_size); }

gsl::span<uint8_t>
apis::io_bitmaps()
{ return gsl::make_span(m_io_bitmaps.get(), ::x64::pt::page_size * 2); }

//==========================================================================
// Resources
//==========================================================================

void
apis::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handler->add_handler(reason, std::move(d)); }

//==========================================================================
// Private
//==========================================================================

void
apis::check_crall()
{
    if (!m_control_register_handler) {
        m_control_register_handler = std::make_unique<control_register_handler>(this);
    }
}

void
apis::check_rdcr3()
{
    check_crall();

    if (!m_is_rdcr3_enabled) {
        m_is_rdcr3_enabled = true;
        m_control_register_handler->enable_rdcr3_exiting();
    }
}

void
apis::check_wrcr3()
{
    check_crall();

    if (!m_is_wrcr3_enabled) {
        m_is_wrcr3_enabled = true;
        m_control_register_handler->enable_wrcr3_exiting();
    }
}

void
apis::check_io_bitmaps()
{
    using namespace vmcs_n;

    if (!m_io_bitmaps) {
        m_io_bitmaps = std::make_unique<uint8_t[]>(::x64::pt::page_size * 2);

        address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(&m_io_bitmaps[0x0000]));
        address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(&m_io_bitmaps[010000]));

        primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
    }
}

void
apis::check_msr_bitmap()
{
    using namespace vmcs_n;

    if (!m_msr_bitmap) {
        m_msr_bitmap = std::make_unique<uint8_t[]>(::x64::pt::page_size);

        address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
        primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
    }
}

void
apis::check_rdmsr_handler()
{
    check_msr_bitmap();

    if (!m_rdmsr_handler) {
        m_rdmsr_handler = std::make_unique<rdmsr_handler>(this);
    }
}

void
apis::check_wrmsr_handler()
{
    check_msr_bitmap();

    if (!m_wrmsr_handler) {
        m_wrmsr_handler = std::make_unique<wrmsr_handler>(this);
    }
}

}
}
