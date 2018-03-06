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

#ifndef PHYS_LAPIC_INTEL_X64_EAPIS_H
#define PHYS_LAPIC_INTEL_X64_EAPIS_H

#include "base.h"

namespace eapis
{
namespace intel_x64
{

/// Local APIC base class
///
///
///
struct EXPORT_EAPIS_VIC phys_lapic
{
    using gpa_t = uintptr_t;
    using value_t = uint64_t;
    using field_t = ::intel_x64::msrs::field_type;
    using vector_t = ::intel_x64::msrs::value_type;

    enum index : uint32_t { idx0, idx1, idx2, idx3, idx4, idx5, idx6, idx7 };
    enum lvt_reg : uint32_t { cmci, timer, thermal, perf, lint0, lint1, error };
    enum count_reg : uint32_t { initial, current };
    enum reg_op : uint32_t { read, write };

    /// Default constructor
    ///
    /// @expects
    /// @ensures
    ///
    phys_lapic() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    virtual ~phys_lapic() = default;

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
    /// @param op - the desired operation (read / write)
    ///
    virtual int check_gpa_op(const gpa_t addr, const reg_op op) = 0;

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
    /// @param op - the desired operation (read / write)
    ///
    virtual int check_msr_op(const field_t msr, const reg_op op) = 0;

    /// @cond

    virtual value_t read_reg(const uint32_t offset) = 0;
    virtual void write_reg(const uint32_t offset, const value_t val) = 0;

    /// @endcond

    ///
    /// The following functions provide a common interface for reading
    /// and writing the physical local APIC. It is somewhat of a union
    /// between the MMIO interface specified in Table 10.1 and the
    /// MSR interface described in Table 10.6 of the SDM.
    ///

    ///
    /// Register reads
    ///
    virtual value_t read_id() = 0;
    virtual value_t read_version() = 0;
    virtual value_t read_tpr() = 0;
    virtual value_t read_ldr() = 0;
    virtual value_t read_svr() = 0;
    virtual value_t read_icr() = 0;
    virtual value_t read_isr(const index idx) = 0;
    virtual value_t read_tmr(const index idx) = 0;
    virtual value_t read_irr(const index idx) = 0;
    virtual value_t read_lvt(const lvt_reg reg) = 0;
    virtual value_t read_count(const count_reg reg) = 0;
    virtual value_t read_div_config() = 0;

    ///
    /// Register writes
    ///
    virtual void write_eoi() = 0;
    virtual void write_tpr(const value_t tpr) = 0;
    virtual void write_svr(const value_t svr) = 0;
    virtual void write_icr(const value_t icr) = 0;
    virtual void write_lvt(const lvt_reg reg, const value_t val) = 0;
    virtual void write_init_count(const value_t count) = 0;
    virtual void write_div_config(const value_t config) = 0;

    ///
    /// Send a self-ipi
    ///
    /// A self-ipi is a self-targeted, edge-triggered, fixed interrupt
    /// with the specified vector.
    ///
    /// @param vec - the vector of the self-ipi
    ///
    virtual void write_self_ipi(const vector_t vec) = 0;

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
    virtual bool level_triggered(const vector_t vec) = 0;

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
    virtual bool in_service(const vector_t vec) = 0;

    /// @cond

    phys_lapic(phys_lapic &&) = default;
    phys_lapic &operator=(phys_lapic &&) = default;

    phys_lapic(const phys_lapic &) = delete;
    phys_lapic &operator=(const phys_lapic &) = delete;

    /// @endcond
};

}
}

#endif
