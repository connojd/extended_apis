//
// Bareflank Hypervisor
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

#ifndef PHYS_X2APIC_INTEL_X64_EAPIS_H
#define PHYS_X2APIC_INTEL_X64_EAPIS_H

#include "phys_lapic.h"

namespace eapis
{
namespace intel_x64
{

/// x2APIC subclass of the phys_lapic abstract base class
///
/// This class implements the physical lapic interface for x2apic
/// mode. It is marked final because it is intended to interact
/// directly with x2apic hardware, and thus attempts to avoid the
/// overhead of virtualized calls as much as possible.
///
struct EXPORT_EAPIS_VIC phys_x2apic : public phys_lapic
{
    /// Default constructor
    ///
    /// @expects
    /// @ensures
    ///
    phys_x2apic() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~phys_x2apic() = default;

    /// Check GPA operation
    ///
    /// Check if guest physical address is an APIC register and the desired
    /// read / write operation is allowed.
    ///
    /// @return offset if supplied address maps to a valid register and the
    ///    operation is allowed.
    /// @return -1 if the supplied address doesn't map to a valid register or the
    ///    operation is not allowed.
    ///
    /// @param addr - guest physical address of desired register
    /// @param op - the desired operation (@see phys_lapic:reg_op)
    ///
    int check_gpa_op(const gpa_t addr, const reg_op op) noexcept;

    /// Check MSR operation
    ///
    /// Check if MSR address is an APIC register and the desired read / write
    /// operation is allowed.
    ///
    /// @return offset if supplied address maps to a valid register and the
    ///    operation is allowed.
    /// @return -1 if the supplied address doesn't map to a valid register or the
    ///    operation is not allowed.
    ///
    /// @param addr - MSR address of desired register
    /// @param op - the desired operation (@see phys_lapic::reg_op)
    ///
    int check_msr_op(const field_t msr, const reg_op op) noexcept;

    /// @cond

    value_t read_reg(const uint32_t offset) noexcept;
    void write_reg(const uint32_t offset, const value_t val) noexcept;

    /// @endcond

    ///
    /// Register reads
    ///
    value_t read_id() noexcept;
    value_t read_version() noexcept;
    value_t read_tpr() noexcept;
    value_t read_ldr() noexcept;
    value_t read_svr() noexcept;
    value_t read_icr() noexcept;
    value_t read_isr(const index idx) noexcept;
    value_t read_tmr(const index idx) noexcept;
    value_t read_irr(const index idx) noexcept;
    value_t read_lvt(const lvt_reg reg) noexcept;
    value_t read_count(const count_reg reg) noexcept;
    value_t read_div_config() noexcept;

    ///
    /// Register writes
    ///
    void write_eoi() noexcept;
    void write_tpr(const value_t tpr) noexcept;
    void write_svr(const value_t svr) noexcept;
    void write_icr(const value_t icr) noexcept;
    void write_lvt(const lvt_reg reg, const value_t val) noexcept;
    void write_init_count(const value_t count) noexcept;
    void write_div_config(const value_t config) noexcept;

    ///
    /// Send a self-ipi
    ///
    /// A self-ipi is a self-targeted, edge-triggered, fixed interrupt
    /// with the specified vector.
    ///
    /// @param vec - the vector of the self-ipi
    ///
    void write_self_ipi(const vector_t vec) noexcept;

    ///
    /// Check trigger-mode
    ///
    /// @return true if the supplied vector is set in the TMR
    /// @return false if the supplied vector is clear in the TMR
    ///
    /// @param vec - the vector for which the check occurs.
    ///
    /// @note to ensure an accurate result, the caller should mask
    /// the vector prior to the call
    ///
    bool level_triggered(const vector_t vec) noexcept;

    ///
    /// Check if in-service
    ///
    /// @return true if the supplied vector is set in the ISR
    /// @return false if the supplied vector is clear in the ISR
    ///
    /// @param vec - the vector for which the check occurs.
    ///
    /// @note to ensure an accurate result, the caller should mask
    /// the vector prior to the call
    ///
    bool in_service(const vector_t vec) noexcept;

    /// @cond

    phys_x2apic(phys_x2apic &&) = default;
    phys_x2apic &operator=(phys_x2apic &&) = default;

    phys_x2apic(const phys_x2apic &) = delete;
    phys_x2apic &operator=(const phys_x2apic &) = delete;

    /// @endcond
};

}
}

#endif
