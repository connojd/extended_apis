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
#include <hve/arch/intel_x64/vcpu.h>
#include <vic/arch/intel_x64/virt_x2apic.h>

namespace eapis
{
namespace intel_x64
{

virt_x2apic::virt_x2apic(gsl::not_null<eapis::intel_x64::vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    this->reset_registers();
}

void
virt_x2apic::reset_registers()
{
    for (const auto &pair: ::intel_x64::lapic::registers::info_map) {
        const auto reg = pair.second;
        if (::intel_x64::lapic::registers::exists_in_x2apic(reg.offset)) {
            this->reset_register(reg.offset);
        }
    }
}

uint64_t
virt_x2apic::read_register(uint64_t offset) const
{ return m_registers.at(offset); }

uint64_t
virt_x2apic::read_id() const
{ return m_registers.at(::intel_x64::lapic::registers::id.offset); }

uint64_t
virt_x2apic::read_version() const
{ return m_registers.at(::intel_x64::lapic::registers::version.offset); }

uint64_t
virt_x2apic::read_tpr() const
{ return m_registers.at(::intel_x64::lapic::registers::tpr.offset); }

uint64_t
virt_x2apic::read_icr() const
{ return m_registers.at(::intel_x64::lapic::registers::icr0.offset); }

void
virt_x2apic::write_register(uint64_t offset, uint64_t val)
{ m_registers.at(offset) = val; }

void
virt_x2apic::write_eoi()
{ m_registers.at(::intel_x64::lapic::registers::eoi.offset) = 0x0ULL; }

void
virt_x2apic::write_tpr(uint64_t tpr)
{ m_registers.at(::intel_x64::lapic::registers::tpr.offset) = tpr; }

void
virt_x2apic::write_icr(uint64_t icr)
{ m_registers.at(::intel_x64::lapic::registers::icr0.offset) = icr; }

uint64_t
virt_x2apic::max_lvt_entry() const
{
    const auto &version = m_registers.at(
        ::intel_x64::lapic::registers::version.offset
    );

    return ::intel_x64::lapic::version::max_lvt_entry_minus_one::get(version) + 1U;
}

///-----------------------------------------------------------------------------
/// Private
///-----------------------------------------------------------------------------

void
virt_x2apic::insert(uint64_t offset, uint64_t value)
{ m_registers[offset] = value; }

void
virt_x2apic::reset_id()
{ insert(::intel_x64::lapic::registers::id.offset, m_vcpu->id()); }

///
/// See Table 10-7 in the SDM
///
void
virt_x2apic::reset_version()
{
    static_assert(::intel_x64::lapic::lvt::default_size > 0, "Need LVT size > 0");
    const auto lvt_limit = ::intel_x64::lapic::lvt::default_size - 1U;

    auto val = 0U;
    val |= ::intel_x64::lapic::version::version::set(val, ::intel_x64::lapic::version::version::reset_value);
    val |= ::intel_x64::lapic::version::max_lvt_entry_minus_one::set(val, lvt_limit);
    val |= ::intel_x64::lapic::version::suppress_eoi_broadcast_supported::disable(val);

    insert(::intel_x64::lapic::registers::version.offset, val);
}

void
virt_x2apic::reset_svr()
{ insert(::intel_x64::lapic::registers::svr.offset, ::intel_x64::lapic::svr::reset_value); }

void
virt_x2apic::reset_lvt_register(uint64_t offset)
{ insert(offset, ::intel_x64::lapic::lvt::reset_value); }

void
virt_x2apic::clear_register(uint64_t offset)
{ insert(offset, 0U); }

void
virt_x2apic::reset_register(uint64_t offset)
{
    switch (offset) {
        case ::intel_x64::lapic::registers::id.offset:
            this->reset_id();
            break;

        case ::intel_x64::lapic::registers::version.offset:
            this->reset_version();
            break;

        case ::intel_x64::lapic::registers::tpr.offset:
        case ::intel_x64::lapic::registers::ppr.offset:
        case ::intel_x64::lapic::registers::eoi.offset:
        case ::intel_x64::lapic::registers::ldr.offset:

        case ::intel_x64::lapic::registers::isr0.offset:
        case ::intel_x64::lapic::registers::isr1.offset:
        case ::intel_x64::lapic::registers::isr2.offset:
        case ::intel_x64::lapic::registers::isr3.offset:
        case ::intel_x64::lapic::registers::isr4.offset:
        case ::intel_x64::lapic::registers::isr5.offset:
        case ::intel_x64::lapic::registers::isr6.offset:
        case ::intel_x64::lapic::registers::isr7.offset:

        case ::intel_x64::lapic::registers::tmr0.offset:
        case ::intel_x64::lapic::registers::tmr1.offset:
        case ::intel_x64::lapic::registers::tmr2.offset:
        case ::intel_x64::lapic::registers::tmr3.offset:
        case ::intel_x64::lapic::registers::tmr4.offset:
        case ::intel_x64::lapic::registers::tmr5.offset:
        case ::intel_x64::lapic::registers::tmr6.offset:
        case ::intel_x64::lapic::registers::tmr7.offset:

        case ::intel_x64::lapic::registers::irr0.offset:
        case ::intel_x64::lapic::registers::irr1.offset:
        case ::intel_x64::lapic::registers::irr2.offset:
        case ::intel_x64::lapic::registers::irr3.offset:
        case ::intel_x64::lapic::registers::irr4.offset:
        case ::intel_x64::lapic::registers::irr5.offset:
        case ::intel_x64::lapic::registers::irr6.offset:
        case ::intel_x64::lapic::registers::irr7.offset:

        case ::intel_x64::lapic::registers::esr.offset:
        case ::intel_x64::lapic::registers::icr0.offset:
        case ::intel_x64::lapic::registers::div_conf.offset:
        case ::intel_x64::lapic::registers::init_count.offset:
        case ::intel_x64::lapic::registers::cur_count.offset:
        case ::intel_x64::lapic::registers::self_ipi.offset:
            this->clear_register(offset);
            break;

        case ::intel_x64::lapic::registers::lvt_cmci.offset:
        case ::intel_x64::lapic::registers::lvt_timer.offset:
        case ::intel_x64::lapic::registers::lvt_thermal.offset:
        case ::intel_x64::lapic::registers::lvt_pmi.offset:
        case ::intel_x64::lapic::registers::lvt_lint0.offset:
        case ::intel_x64::lapic::registers::lvt_lint1.offset:
        case ::intel_x64::lapic::registers::lvt_error.offset:
            this->reset_lvt_register(offset);
            break;

        case ::intel_x64::lapic::registers::svr.offset:
            this->reset_svr();
            break;

        default:
            bferror_nhex(0, "virt_x2apic: unhandled register reset", offset);
            throw std::invalid_argument(
                "unknown register offset to reset: " + std::to_string(offset));
            break;
    }
}

}
}
