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

#ifndef MTRR_INTEL_X64_EAPIS_H
#define MTRR_INTEL_X64_EAPIS_H

#include <cstdint>
#include <arch/x64/misc.h>
#include <arch/intel_x64/mtrr.h>
#include "base.h"
#include "hve.h"

namespace eapis
{
namespace intel_x64
{
namespace mtrr
{

/// Page frame number mask (for 4K pages)
constexpr uint64_t pfn_mask_4k = ~(0x1000U - 1U);

/// Extract the mask from a ia32_physmask{n} msr
///
/// @param mask_msr the value of the ia32_physmask msr
/// @param pas the number of physical address bits
///
inline uint64_t mask_msr_to_mask(uint64_t mask_msr, uint64_t pas)
{
    const uint64_t from = ::intel_x64::mtrr::physmask::physmask::from;
    return ::intel_x64::mtrr::physmask::physmask::get(mask_msr, pas) << from;
}

/// Extract the size of a range from a ia32_physmask{n} msr
///
/// @param mask_msr the value of the ia32_physmask msr
/// @param pas the number of physical address bits
///
inline uint64_t mask_msr_to_size(uint64_t mask_msr, uint64_t pas)
{
    const uint64_t bits = ((1ULL << pas) - 1U);
    const uint64_t mask = mask_msr_to_mask(mask_msr, pas);
    return (~mask & bits) + 1U;
}

/// Extract the base of the range from a ia32_physbase{n} msr
///
/// @param base_msr the value of the ia32_physbase msr
/// @param pas the number of physical address bits
///
inline uint64_t base_msr_to_base(uint64_t base_msr, uint64_t pas)
{
    const uint64_t from = ::intel_x64::mtrr::physbase::physbase::from;
    return ::intel_x64::mtrr::physbase::physbase::get(base_msr, pas) << from;
}

/// base_msr_to_type
///
/// Extract the type of the range from a ia32_physbase{n} msr
///
/// @param base_msr the value of the ia32_physbase msr
/// @param pas the number of physical address bits
///
inline uint64_t base_msr_to_type(uint64_t base_msr)
{ return ::intel_x64::mtrr::physbase::type::get(base_msr); }

/// size_to_mask
///
/// Convert the range size to the corresponding mask
///
/// @param size the size of the range
/// @param pas the number of bits in a physical address
//
/// @return the mask that determines the set of addresses that
///         lie in the range
/// @note @param size should be the value returned from mask_msr_to_size
///
inline uint64_t size_to_mask(uint64_t size, uint64_t pas)
{
    const uint64_t bits = ((1ULL << pas) - 1U);
    return ~(size - 1U) & bits;
}

/// mask_to_size
///
/// Convert the range mask to the corresponding size
///
/// @param mask the mask of the range
/// @param pas the number of bits in a physical address
//
/// @return the mask that determines the set of addresses that
///         lie in the range
/// @note @param mask should be the value returned from mask_msr_to_mask
///
inline uint64_t mask_to_size(uint64_t mask, uint64_t pas)
{
    const uint64_t bits = ((1ULL << pas) - 1U);
    return (~mask & bits) + 1U;
}

/// Variable MTRR range
///
///
struct variable_range {

    /// Constructor
    ///
    /// Create a variable range from the physbase and physmask
    /// msr values provided. Note that the values are checked to
    /// ensure that any struct variable_range this is created is valid.
    ///
    /// @param base_msr the value of the ia32_physbase msr
    /// @param mask_msr the value of the ia32_physmask msr
    /// @param pas the number of physical address bits
    ///
    variable_range(uint64_t base_msr, uint64_t mask_msr, uint64_t pas)
    {
        const uint64_t type = base_msr_to_type(base_msr);
        const uint64_t base = base_msr_to_base(base_msr, pas);
        const uint64_t size = mask_msr_to_size(mask_msr, pas);
        constexpr uint64_t min_size = 0x1000U;

        expects(pas >= 39U && pas <= 52U);
        expects(::intel_x64::mtrr::valid_type(type));
        expects(x64::is_physical_address_valid(base, pas));
        expects(size >= min_size);
        expects(base >= size);
        expects((size & (size - 1U)) == 0U);
        expects((base & (base - 1U)) == 0U);
        expects((base + size) > base);

        m_base_msr = base_msr;
        m_mask_msr = mask_msr;
        m_pas = pas;
    }

    /// base
    ///
    /// @return the base address
    ///
    uintptr_t base() const
    { return base_msr_to_base(m_base_msr, m_pas); }

    /// type
    ///
    /// @return the memory type of the range
    ///
    uint64_t type() const
    { return base_msr_to_type(m_base_msr); }

    /// mask
    ///
    /// @return the range mask
    ///
    uintptr_t mask() const
    { return mask_msr_to_mask(m_mask_msr, m_pas); }

    /// size
    ///
    /// @return the number of bytes in the range
    ///
    uintptr_t size() const
    { return mask_msr_to_size(m_mask_msr, m_pas); }

    /// contains
    ///
    /// @param addr the address to check
    /// @return true iff the range contains the given address
    ///
    bool contains(uintptr_t addr) const
    {
        const uint64_t mask = mask_msr_to_mask(m_mask_msr, m_pas);
        const uint64_t base = base_msr_to_base(m_base_msr, m_pas);
        return (mask & base) == (mask & addr);
    }

    /// @cond

    uint64_t m_base_msr;
    uint64_t m_mask_msr;
    uint64_t m_pas;

    /// @endcond
};

}
}
}

#endif
