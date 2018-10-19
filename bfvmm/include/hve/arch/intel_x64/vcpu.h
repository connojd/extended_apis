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

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

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

    /// Add CPUID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param d the delegate to call when the guest executes CPUID
    ///
    VIRTUAL void add_cpuid_handler(
        cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d);

    /// Add CPUID Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes CPUID
    ///
    VIRTUAL void add_default_cpuid_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // EPT Misconfiguration
    //--------------------------------------------------------------------------

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

    /// Trap All IO Instruction Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_io_instruction_accesses();

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

    /// Trap On Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    VIRTUAL void trap_on_rdmsr_access(vmcs_n::value_type msr);

    /// Trap All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_rdmsr_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    VIRTUAL void pass_through_rdmsr_access(vmcs_n::value_type msr);

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

    /// Add Read MSR Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes rdmsr
    ///
    VIRTUAL void add_default_rdmsr_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Write MSR
    //--------------------------------------------------------------------------

    /// Trap On Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    VIRTUAL void trap_on_wrmsr_access(vmcs_n::value_type msr);

    /// Trap All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_wrmsr_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    VIRTUAL void pass_through_wrmsr_access(vmcs_n::value_type msr);

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

    /// Add Write MSR Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes wrmsr
    ///
    VIRTUAL void add_default_wrmsr_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // XSetBV
    //--------------------------------------------------------------------------

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

    VIRTUAL gsl::not_null<vcpu_global_state_t *> global_state() const
    { return m_vcpu_global_state; }

    //==========================================================================
    // Memory Mapping
    //==========================================================================

    /// Get Entry
    ///
    /// Given a GPA to a pml4, pdpt, pd or pt and an index, this function will
    /// return the table entry.
    ///
    /// @param tble_gpa the guest physical address of the table to
    ///     get the entry from.
    /// @param index the index into the table
    /// @return tble_gpa[index]
    ///
    uintptr_t get_entry(uintptr_t tble_gpa, std::ptrdiff_t index);

    /// Get Entry Delegate Instance
    ///
    /// The following is an instantiation of the get_entry delegate that can
    /// be used for getting a PTE if the GPA == the HPA
    ///
    bfvmm::x64::get_entry_delegate_t get_entry_delegate =
        bfvmm::x64::get_entry_delegate_t::create<vcpu, &vcpu::get_entry>(this);

    /// Convert GPA to HPA
    ///
    /// Converts a guest physical address to a host physical address
    /// using EPT. If EPT is not enabled, this function will return
    /// the GPA (as the HPA == the GPA), and "from" will be set to 0 as
    /// this information is not available.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gpa_to_hpa(uint64_t gpa);

    /// Convert GVA to GPA
    ///
    /// Converts a guest virtual address to a guest physical address
    /// using EPT.
    ///
    /// Note:
    /// - This function assumes that this vCPU is loaded when you run this
    ///   function. If this vCPU is not loaded, you will end up parsing the
    ///   GVA associated with whatever vCPU is currently loaded leading to
    ///   possible corruption. The reason for this is this function uses
    ///   the VMCS's guest_cr3.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting guest physical address
    ///
    std::pair<uintptr_t, uintptr_t> gva_to_gpa(uint64_t gva);

    /// Convert GVA to HPA
    ///
    /// Converts a guest virtual address to a host physical address
    /// using EPT.
    ///
    /// Note:
    /// - This function assumes that this vCPU is loaded when you run this
    ///   function. If this vCPU is not loaded, you will end up parsing the
    ///   GVA associated with whatever vCPU is currently loaded leading to
    ///   possible corruption. The reason for this is this function uses
    ///   the VMCS's guest_cr3.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gva_to_hpa(uint64_t gva);

    /// Map GPA to HPA 1g
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT. This does NOT map the GPA to the VMM. This simply adds
    /// an entry to EPT.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_gpa_to_hpa_1g(uintptr_t gpa, uintptr_t hpa);

    /// Map GPA to HPA 2m
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT. This does NOT map the GPA to the VMM. This simply adds
    /// an entry to EPT.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_gpa_to_hpa_2m(uintptr_t gpa, uintptr_t hpa);

    /// Map GPA to HPA 4k
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT. This does NOT map the GPA to the VMM. This simply adds
    /// an entry to EPT.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_gpa_to_hpa_4k(uintptr_t gpa, uintptr_t hpa);

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost, and the resulting map
    /// is accessible from the VMM
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(uintptr_t gpa)
    {
        auto [hpa, unused] = this->gpa_to_hpa(gpa);
        return bfvmm::x64::map_hpa_1g<T>(hpa);
    }

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost, and the resulting map
    /// is accessible from the VMM
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(void *gpa)
    { return map_gpa_1g<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost, and the resulting map
    /// is accessible from the VMM
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(uintptr_t gpa)
    {
        auto [hpa, unused] = this->gpa_to_hpa(gpa);
        return bfvmm::x64::map_hpa_2m<T>(hpa);
    }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost, and the resulting map
    /// is accessible from the VMM
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(void *gpa)
    { return map_gpa_2m<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost, and the resulting map
    /// is accessible from the VMM
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(uintptr_t gpa)
    {
        auto [hpa, unused] = this->gpa_to_hpa(gpa);
        return bfvmm::x64::map_hpa_4k<T>(hpa);
    }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost, and the resulting map
    /// is accessible from the VMM
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(void *gpa)
    { return map_gpa_4k<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GVA (4k)
    ///
    /// Map a 4k guest virtual address. This function will automatically convert
    /// the provided GVA to a HPA and then map The result of this function is
    /// a unique_map that will unmap when scope is lost, and the map's pointer
    /// will be properly positioned to align with lower bits of the provided
    /// GVA (meaning, the GVA does not need to be page aligned, and any offset
    /// in the GVA will be reflected in the provided map). Also note that the
    /// map provides access to the GVA from the VMM.
    ///
    /// Note:
    /// - This function assumes that this vCPU is loaded when you run this
    ///   function. If this vCPU is not loaded, you will end up parsing the
    ///   GVA associated with whatever vCPU is currently loaded leading to
    ///   possible corruption. The reason for this is this function uses
    ///   the VMCS's guest_cr3.
    ///
    /// @expects
    ///
    /// @param gva the guest virtual address
    /// @param len the number of bytes to map
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gva_4k(uintptr_t gva, std::size_t len)
    {
        return
            bfvmm::x64::map_gva_4k<T>(
                gva,
                vmcs_n::guest_cr3::get(),
                len,
                get_entry_delegate
            );
    }

    /// Map GVA (4k)
    ///
    /// Map a 4k guest virtual address. This function will automatically convert
    /// the provided GVA to a HPA and then map The result of this function is
    /// a unique_map that will unmap when scope is lost, and the map's pointer
    /// will be properly positioned to align with lower bits of the provided
    /// GVA (meaning, the GVA does not need to be page aligned, and any offset
    /// in the GVA will be reflected in the provided map). Also note that the
    /// map provides access to the GVA from the VMM.
    ///
    /// Note:
    /// - This function assumes that this vCPU is loaded when you run this
    ///   function. If this vCPU is not loaded, you will end up parsing the
    ///   GVA associated with whatever vCPU is currently loaded leading to
    ///   possible corruption. The reason for this is this function uses
    ///   the VMCS's guest_cr3.
    ///
    /// @expects
    ///
    /// @param gva the guest virtual address
    /// @param len the number of bytes to map
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gva_4k(void *gva, std::size_t len)
    { return map_gva_4k<T>(reinterpret_cast<uintptr_t>(gva), len); }

private:

    vcpu_global_state_t *m_vcpu_global_state;

private:

    std::unique_ptr<uint8_t, void(*)(void *)> m_msr_bitmap;
    std::unique_ptr<uint8_t, void(*)(void *)> m_io_bitmap_a;
    std::unique_ptr<uint8_t, void(*)(void *)> m_io_bitmap_b;

    ept::mmap *m_mmap;

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

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

// Note:
//
// Undefine previously defined helper macros. Note that these are used by
// each extension to provide quick access to the vcpu in the extension. If
// include files are not handled properly, you could end up with the wrong
// vcpu, resulting in compilation errors
//

#ifdef get_vcpu
#undef get_vcpu
#endif

#ifdef vcpu_cast
#undef vcpu_cast
#endif

/// Get Guest vCPU
///
/// Gets a guest vCPU from the vCPU manager given a vcpuid
///
/// @expects
/// @ensures
///
/// @return returns a pointer to the vCPU being queried or throws
///     and exception.
///
#define get_vcpu(a) \
    g_vcm->get<eapis::intel_x64::vcpu *>(a, __FILE__ ": invalid eapis vcpuid")

#define vcpu_cast(a) \
    static_cast<eapis::intel_x64::vcpu *>(a.get())

}

#endif
