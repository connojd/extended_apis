//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef X2APIC_CTL_INTEL_X64_EAPIS_H
#define X2APIC_CTL_INTEL_X64_EAPIS_H

#include <set>
#include <intrinsics.h>

#include "lapic_ctl.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_VIC
#ifdef SHARED_VIC
#define EXPORT_VIC EXPORT_SYM
#else
#define EXPORT_VIC IMPORT_SYM
#endif
#else
#define EXPORT_VIC
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace eapis
{
namespace intel_x64
{

namespace x2apic = ::intel_x64::x2apic;

/// x2APIC subclass of the lapic abstract base class
///
/// This class implements the abstract lapic interface for x2apic
/// mode. It is marked final because it is intended to interact
/// directly with x2apic hardware.
///
struct EXPORT_VIC x2apic_ctl final : public lapic_ctl
{
    using gpa_t = lapic_ctl::gpa_t;
    using field_t = lapic_ctl::field_t;
    using value_t = lapic_ctl::value_t;
    using vector_t = lapic_ctl::vector_t;

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
    virtual int check_gpa_op(const gpa_t addr, const reg_op op) noexcept override;

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
    virtual int check_msr_op(const field_t msr, const reg_op op) noexcept override;

    virtual value_t read_register(const uint32_t offset) noexcept override;
    virtual void write_register(const uint32_t offset, const value_t val) noexcept override;

    ///
    /// Register reads
    ///
    virtual value_t read_id() noexcept override;
    virtual value_t read_version() noexcept override;
    virtual value_t read_tpr() noexcept override;
    virtual value_t read_ldr() noexcept override;
    virtual value_t read_svr() noexcept override;
    virtual value_t read_icr() noexcept override;
    virtual value_t read_isr(const index idx) noexcept override;
    virtual value_t read_tmr(const index idx) noexcept override;
    virtual value_t read_irr(const index idx) noexcept override;
    virtual value_t read_lvt(const lvt_reg reg) noexcept override;
    virtual value_t read_count(const count_reg reg) noexcept override;
    virtual value_t read_div_config() noexcept override;

    ///
    /// Register writes
    ///
    virtual void write_eoi() noexcept override;
    virtual void write_tpr(const value_t tpr) noexcept override;
    virtual void write_svr(const value_t svr) noexcept override;
    virtual void write_icr(const value_t icr) noexcept override;
    virtual void write_lvt(const lvt_reg reg, const value_t val) noexcept override;
    virtual void write_init_count(const value_t count) noexcept override;
    virtual void write_div_config(const value_t config) noexcept override;

    ///
    /// Send a self-ipi
    ///
    /// A self-ipi is a self-targeted, edge-triggered, fixed interrupt
    /// with the specified vector.
    ///
    /// @param vec - the vector of the self-ipi
    ///
    virtual void write_self_ipi(const vector_t vec) noexcept override;

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
    virtual bool level_triggered(const vector_t vec) noexcept override;

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
    virtual bool in_service(const vector_t vec) noexcept override;

    ///
    /// Default operations
    ///
    /// @cond

    virtual ~x2apic_ctl() = default;
    x2apic_ctl() = default;
    x2apic_ctl(x2apic_ctl &&) = default;
    x2apic_ctl &operator=(x2apic_ctl &&) = default;

    x2apic_ctl(const x2apic_ctl &) = delete;
    x2apic_ctl &operator=(const x2apic_ctl &) = delete;

    /// @endcond
};

}
}

#endif
