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

#ifndef PHYS_LAPIC_INTEL_X64_EAPIS_H
#define PHYS_LAPIC_INTEL_X64_EAPIS_H

#include "base.h"

namespace eapis
{
namespace intel_x64
{

struct EXPORT_EAPIS_VIC phys_lapic
{
    /// Default Constructor
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

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the canonical offset to read
    ///
    virtual uint64_t read_register(uint64_t offset) = 0;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the canonical offset to write
    /// @param val the value to write
    ///
    virtual void write_register(uint64_t offset, uint64_t val) = 0;

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
