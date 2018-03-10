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

#ifndef PHYS_X2APIC_INTEL_X64_EAPIS_H
#define PHYS_X2APIC_INTEL_X64_EAPIS_H

#include "lapic.h"

namespace eapis
{
namespace intel_x64
{

/// Physical x2APIC
///
/// This class implements the lapic interface for x2apic
/// mode. It is marked final because it is intended to interact
/// directly with x2apic hardware.
///
struct EXPORT_EAPIS_VIC phys_x2apic final : public lapic
{
    /// Default Constructor
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
    virtual ~phys_x2apic() = default;

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the canonical offset to read
    ///
    virtual uint64_t read_register(uint64_t offset) const override;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the canonical offset to write
    /// @param val the value to write
    ///
    virtual void write_register(uint64_t offset, uint64_t val) override;

    /// @endcond

    ///
    /// Register reads
    ///
    uint64_t read_id() const;
    uint64_t read_version() const;
    uint64_t read_tpr() const;
    uint64_t read_svr() const;
    uint64_t read_icr() const;

    ///
    /// Register writes
    ///
    void write_eoi();
    void write_tpr(uint64_t tpr);
    void write_svr(uint64_t svr);
    void write_icr(uint64_t icr);

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
