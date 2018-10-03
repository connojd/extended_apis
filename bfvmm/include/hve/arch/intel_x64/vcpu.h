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

#ifndef VCPU_INTEL_X64_EAPIS_H
#define VCPU_INTEL_X64_EAPIS_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

#include "vmexit/control_register.h"
#include "vmexit/cpuid.h"
#include "vmexit/ept_misconfiguration.h"
#include "vmexit/ept_violation.h"
#include "vmexit/external_interrupt.h"
#include "vmexit/init_signal.h"
#include "vmexit/interrupt_window.h"
#include "vmexit/io_instruction.h"
#include "vmexit/monitor_trap.h"
#include "vmexit/rdmsr.h"
#include "vmexit/sipi_signal.h"
#include "vmexit/wrmsr.h"
#include "vmexit/xsetbv.h"

#include "ept.h"
#include "interrupt_queue.h"
#include "microcode.h"
#include "vcpu_global_state.h"
#include "vpid.h"

namespace eapis::intel_x64
{

class vcpu :
    public bfvmm::intel_x64::vcpu
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    /// @param vcpu_global_state a pointer to the vCPUs state
    ///
    explicit vcpu(
        vcpuid::type id,
        vcpu_global_state_t *vcpu_global_state = nullptr);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

public:

    //==========================================================================
    // MISC
    //==========================================================================

    //--------------------------------------------------------------------------
    // EPT
    //--------------------------------------------------------------------------

    /// Get EPT Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT handler stored in the apis if EPT is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<ept_handler *> ept();

    /// Set EPTP
    ///
    /// Enables EPT and sets the EPTP to point to the provided mmap.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The map to set EPTP to.
    ///
    VIRTUAL void set_eptp(ept::mmap &map);

    /// Disable EPT
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_ept();

    //--------------------------------------------------------------------------
    // VPID
    //--------------------------------------------------------------------------

    /// Get VPID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the VPID handler stored in the apis if VPID is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<vpid_handler *> vpid();

    /// Enable VPID
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_vpid();

    /// Disable VPID
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_vpid();

    //==========================================================================
    // VMExit
    //==========================================================================

    //--------------------------------------------------------------------------
    // Control Register
    //--------------------------------------------------------------------------

    /// Get Control Register Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CR handler stored in the apis if CR trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<control_register_handler *> control_register();

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the CR0 enable/disable mask
    /// @param d the delegate to call when a mov-to-cr0 exit occurs
    ///
    VIRTUAL void add_wrcr0_handler(
        vmcs_n::value_type mask,
        const control_register_handler::handler_delegate_t &d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-from-cr3 exit occurs
    ///
    VIRTUAL void add_rdcr3_handler(
        const control_register_handler::handler_delegate_t &d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr3 exit occurs
    ///
    VIRTUAL void add_wrcr3_handler(
        const control_register_handler::handler_delegate_t &d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the CR0 enable/disable mask
    /// @param d the delegate to call when a mov-to-cr4 exit occurs
    ///
    VIRTUAL void add_wrcr4_handler(
        vmcs_n::value_type mask,
        const control_register_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // CPUID
    //--------------------------------------------------------------------------

    /// Get CPUID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CPUID handler stored in the apis if CPUID trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<cpuid_handler *> cpuid();

    /// Add CPUID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param d the delegate to call when the guest executes CPUID at the given
    ///        leaf and subleaf
    ///
    VIRTUAL void add_cpuid_handler(
        cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // EPT Misconfiguration
    //--------------------------------------------------------------------------

    /// Get EPT misconfiguration object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT misconfiguration handler stored in the apis if EPT
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<ept_misconfiguration_handler *> ept_misconfiguration();

    /// Add EPT Misconfiguration Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_misconfiguration_handler(
        const ept_misconfiguration_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // EPT Violation
    //--------------------------------------------------------------------------

    /// Get EPT violation object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT violation handler stored in the apis if EPT
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<ept_violation_handler *> ept_violation();

    /// Add EPT read violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_read_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    /// Add EPT write violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_write_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    /// Add EPT execute violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_execute_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // External Interrupt
    //--------------------------------------------------------------------------

    /// Get External Interrupt Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the external interrupt handler stored in the apis if
    ///     external-interrupt exiting is enabled, otherwise an exception is
    ///     thrown
    ///
    gsl::not_null<external_interrupt_handler *> external_interrupt();

    /// Add External Interrupt Handler
    ///
    /// Turns on external interrupt handling and adds an external interrupt
    /// handler to handle external interrupts
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_external_interrupt_handler(
        const external_interrupt_handler::handler_delegate_t &d);

    /// Disable External Interrupt Support
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_external_interrupts();

    //--------------------------------------------------------------------------
    // Interrupt Window
    //--------------------------------------------------------------------------

    /// Get Interrupt Window Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the interrupt-window handler stored in the apis if
    ///
    gsl::not_null<interrupt_window_handler *> interrupt_window();

    /// Queue External Interrupt
    ///
    /// Queues an external interrupt for injection. If the interrupt window
    /// is open, and there are no interrupts queued for injection, the
    /// interrupt may be injected on the upcoming VM-entry, othewise the
    /// interrupt is queued, and injected when appropriate.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to queue for injection
    ///
    VIRTUAL void queue_external_interrupt(uint64_t vector);

    //--------------------------------------------------------------------------
    // IO Instruction
    //--------------------------------------------------------------------------

    /// Get IO Instruction Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the IO Instruction handler stored in the apis if IO
    ///     Instruction trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<io_instruction_handler *> io_instruction();

    /// Trap All IO Instruction Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_all_io_instruction_accesses();

    /// Pass Through All IO Instruction Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_io_instruction_accesses();

    /// Add IO Instruction Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to call
    /// @param in_d the delegate to call when the reads in from the given port
    /// @param out_d the delegate to call when the guest writes out to the
    ///        given port.
    ///
    VIRTUAL void add_io_instruction_handler(
        vmcs_n::value_type port,
        const io_instruction_handler::handler_delegate_t &in_d,
        const io_instruction_handler::handler_delegate_t &out_d);

    //--------------------------------------------------------------------------
    // Monitor Trap
    //--------------------------------------------------------------------------

    /// Get Monitor Trap Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Monitor Trap handler stored in the apis if Monitor
    ///     Trap is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<monitor_trap_handler *> monitor_trap();

    /// Add Monitor Trap Flag Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a monitor-trap flag exit occurs
    ///
    VIRTUAL void add_monitor_trap_handler(
        const monitor_trap_handler::handler_delegate_t &d);

    /// Enable Monitor Trap Flag
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_monitor_trap_flag();

    //--------------------------------------------------------------------------
    // Read MSR
    //--------------------------------------------------------------------------

    /// Get Read MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Read MSR handler stored in the apis if Read MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<rdmsr_handler *> rdmsr();

    /// Trap All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_all_rdmsr_accesses();

    /// Pass Through All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_rdmsr_accesses();

    /// Add Read MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a rdmsr_handler exit occurs
    ///
    VIRTUAL void add_rdmsr_handler(
        vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Write MSR
    //--------------------------------------------------------------------------

    /// Get Write MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Write MSR handler stored in the apis if Write MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<wrmsr_handler *> wrmsr();

    /// Trap All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_all_wrmsr_accesses();

    /// Pass Through All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_wrmsr_accesses();

    /// Add Write MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a wrmsr_handler exit occurs
    ///
    VIRTUAL void add_wrmsr_handler(
        vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // XSetBV
    //--------------------------------------------------------------------------

    /// Get XSetBV Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the XSetBV handler stored in the apis if XSetBV
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<xsetbv_handler *> xsetbv();

    /// Add XSetBV Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a xsetbv exit occurs
    ///
    VIRTUAL void add_xsetbv_handler(
        const xsetbv_handler::handler_delegate_t &d);

    //==========================================================================
    // Resources
    //==========================================================================

    gsl::not_null<vcpu_global_state_t *> global_state() const
    { return m_vcpu_global_state; }

private:

    bfvmm::intel_x64::vmcs *m_vmcs;
    bfvmm::intel_x64::exit_handler *m_exit_handler;
    vcpu_global_state_t *m_vcpu_global_state;

private:

    std::unique_ptr<uint8_t, void(*)(void *)> m_msr_bitmap;
    std::unique_ptr<uint8_t, void(*)(void *)> m_io_bitmap_a;
    std::unique_ptr<uint8_t, void(*)(void *)> m_io_bitmap_b;

private:

    control_register_handler m_control_register_handler;
    cpuid_handler m_cpuid_handler;
    io_instruction_handler m_io_instruction_handler;
    monitor_trap_handler m_monitor_trap_handler;
    rdmsr_handler m_rdmsr_handler;
    wrmsr_handler m_wrmsr_handler;
    xsetbv_handler m_xsetbv_handler;

    ept_misconfiguration_handler m_ept_misconfiguration_handler;
    ept_violation_handler m_ept_violation_handler;
    external_interrupt_handler m_external_interrupt_handler;
    init_signal_handler m_init_signal_handler;
    interrupt_window_handler m_interrupt_window_handler;
    sipi_signal_handler m_sipi_signal_handler;

    ept_handler m_ept_handler;
    microcode_handler m_microcode_handler;
    vpid_handler m_vpid_handler;

private:

    friend class io_instruction_handler;
    friend class rdmsr_handler;
    friend class wrmsr_handler;
};

}

#endif
