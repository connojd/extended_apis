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

#include <intrinsics.h>
#include <vic/arch/intel_x64/phys_x2apic.h>

namespace eapis
{
namespace intel_x64
{

namespace msrs_n = ::intel_x64::msrs;

uint64_t
phys_x2apic::offset_to_register(uint64_t offset) noexcept
{ return offset | ::intel_x64::lapic::x2apic_base; }

uint64_t
phys_x2apic::read_register(uint64_t offset) noexcept
{ return msrs_n::get(offset_to_register(offset)); }

void
phys_x2apic::write_register(uint64_t offset, uint64_t val) noexcept
{ msrs_n::set(offset_to_register(offset), val); }

uint64_t
phys_x2apic::read_id() noexcept
{ return msrs_n::ia32_x2apic_apicid::get(); }

uint64_t
phys_x2apic::read_version() noexcept
{ return msrs_n::ia32_x2apic_version::get(); }

uint64_t
phys_x2apic::read_tpr() noexcept
{ return msrs_n::ia32_x2apic_tpr::get(); }

uint64_t
phys_x2apic::read_svr() noexcept
{ return msrs_n::ia32_x2apic_sivr::get(); }

uint64_t
phys_x2apic::read_icr() noexcept
{ return msrs_n::ia32_x2apic_icr::get(); }

void
phys_x2apic::write_eoi() noexcept
{ msrs_n::ia32_x2apic_eoi::set(0x0ULL); }

void
phys_x2apic::write_tpr(uint64_t tpr) noexcept
{ msrs_n::ia32_x2apic_tpr::set(tpr); }

void
phys_x2apic::write_svr(uint64_t svr) noexcept
{ msrs_n::ia32_x2apic_sivr::set(svr); }

void
phys_x2apic::write_icr(uint64_t icr) noexcept
{ msrs_n::ia32_x2apic_icr::set(icr); }

}
}
