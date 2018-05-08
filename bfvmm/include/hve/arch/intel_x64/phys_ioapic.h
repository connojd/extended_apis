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

#ifndef PHYS_IOAPIC_INTEL_X64_EAPIS_H
#define PHYS_IOAPIC_INTEL_X64_EAPIS_H

#include <cstdint>
#include "base.h"
#include "ioapic.h"

namespace eapis
{
namespace intel_x64
{

/// Physical IOAPIC
///
/// Provides an interface for reading and writing a physical ioapic.
///
class EXPORT_EAPIS_HVE phys_ioapic
{
public:

    /// Default Constructor
    ///
    /// @expects (base != 0) && aligned(base)
    /// @ensures
    ///
    /// @param base the base address of the ioapic
    ///
    phys_ioapic(ioapic::base_t base);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~phys_ioapic() = default;

    /// Base
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the base address of the physical ioapic
    ///
    ioapic::base_t base() const;

    /// Relocate
    ///
    /// @expects
    /// @ensures
    ///
    /// @param base the new base address of the ioapic
    ///
    void relocate(ioapic::base_t base);

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the offset to read
    /// @return the value of the register at the provided offset
    ///
    ioapic::value_t read_register(ioapic::offset_t offset);

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the offset to write
    /// @param val the 32-bit value to write
    ///
    void write_register(ioapic::offset_t offset, ioapic::value_t val);

    /// @cond

private:

    void set_ioregsel(ioapic::offset_t offset);
    void set_ioregwin(ioapic::value_t val);
    ioapic::value_t get_ioregwin() const;

    ioapic::base_t m_base;

public:

    phys_ioapic(phys_ioapic &&) = default;
    phys_ioapic &operator=(phys_ioapic &&) = default;

    phys_ioapic(const phys_ioapic &) = delete;
    phys_ioapic &operator=(const phys_ioapic &) = delete;

    /// @endcond
};

}
}

#endif
