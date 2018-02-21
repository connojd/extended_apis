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

#include <set>
#include <vic/arch/intel_x64/x2apic_ctl.h>

namespace eapis
{
namespace intel_x64
{

using value_t = x2apic_ctl::value_t;

int
x2apic_ctl::check_gpa_op(const gpa_t addr, const reg_op op) noexcept
{
    auto reg = intel_x2apic::reg_set.find((addr & 0xFF0U) >> 4);

    if (reg != intel_x2apic::reg_set.end()) {
        switch (op) {
            case read:
                if (reg->readable) {
                    return (addr & 0xFF0U) >> 4;
                }
                break;

            case write:
                if (reg->writeable) {
                    return (addr & 0xFF0U) >> 4;
                }
                break;

            default:
                bferror_info(0, "invalid register operation");
                return -1;
        }
    }

    return -1;
}


int
x2apic_ctl::check_msr_op(const field_t msr, const reg_op op) noexcept
{
    if (msr < intel_lapic::msr_start_reg || msr > intel_lapic::msr_end_reg) {
        return -1;
    }
    auto reg = intel_x2apic::reg_set.find(msr & 0xFFU);

    if (reg != intel_x2apic::reg_set.end()) {
        switch (op) {
            case read:
                if (reg->readable) {
                    return msr & 0xFFU;
                }
                break;

            case write:
                if (reg->writeable) {
                    return msr & 0xFFU;
                }
                break;

            default:
                bferror_info(0, "invalid register operation");
                return -1;
        }
    }

    return -1;
}

value_t
x2apic_ctl::read_register(const uint32_t offset) noexcept
{ return intel_msrs::get(offset | intel_lapic::msr_start_reg); }

void
x2apic_ctl::write_register(const uint32_t offset, const value_t val) noexcept
{ intel_msrs::set((offset | intel_lapic::msr_start_reg), val); }

value_t
x2apic_ctl::read_id() noexcept
{ return intel_msrs::ia32_x2apic_apicid::get(); }

value_t
x2apic_ctl::read_version() noexcept
{ return intel_msrs::ia32_x2apic_version::get(); }

value_t
x2apic_ctl::read_tpr() noexcept
{ return intel_msrs::ia32_x2apic_tpr::get(); }

value_t
x2apic_ctl::read_ldr() noexcept
{ return intel_msrs::ia32_x2apic_ldr::get(); }

value_t
x2apic_ctl::read_svr() noexcept
{ return intel_msrs::ia32_x2apic_sivr::get(); }

value_t
x2apic_ctl::read_icr() noexcept
{ return intel_msrs::ia32_x2apic_icr::get(); }

value_t
x2apic_ctl::read_isr(const index idx) noexcept
{
    auto addr = intel_msrs::ia32_x2apic_isr0::addr | idx;
    return intel_msrs::get(addr);
}

value_t
x2apic_ctl::read_tmr(const index idx) noexcept
{
    auto addr = intel_msrs::ia32_x2apic_tmr0::addr | idx;
    return intel_msrs::get(addr);
}

value_t
x2apic_ctl::read_irr(const index idx) noexcept
{
    auto addr = intel_msrs::ia32_x2apic_irr0::addr | idx;
    return intel_msrs::get(addr);
}

value_t
x2apic_ctl::read_lvt(const lvt_reg reg) noexcept
{
    switch (reg) {
        case cmci:
            return intel_msrs::ia32_x2apic_lvt_cmci::get();
        case timer:
            return intel_msrs::ia32_x2apic_lvt_timer::get();
        case thermal:
            return intel_msrs::ia32_x2apic_lvt_thermal::get();
        case perf:
            return intel_msrs::ia32_x2apic_lvt_pmi::get();
        case lint0:
            return intel_msrs::ia32_x2apic_lvt_lint0::get();
        case lint1:
            return intel_msrs::ia32_x2apic_lvt_lint1::get();
        case error:
            return intel_msrs::ia32_x2apic_lvt_error::get();

        default:
            bferror_info(0, "invalid lvt_reg");
            return 0;
    }
}

value_t
x2apic_ctl::read_count(const count_reg reg) noexcept
{
    switch (reg) {
        case initial: return intel_msrs::ia32_x2apic_init_count::get();
        case current: return intel_msrs::ia32_x2apic_cur_count::get();

        default:
            bferror_info(0, "invalid count_reg");
            return 0;
    }
}

value_t
x2apic_ctl::read_div_config() noexcept
{ return intel_msrs::ia32_x2apic_div_conf::get(); }

void
x2apic_ctl:: write_eoi() noexcept
{ intel_msrs::ia32_x2apic_eoi::set(0x0ULL); }

void
x2apic_ctl:: write_tpr(const value_t tpr) noexcept
{ intel_msrs::ia32_x2apic_tpr::set(tpr); }

void
x2apic_ctl:: write_svr(const value_t svr) noexcept
{ intel_msrs::ia32_x2apic_sivr::set(svr); }

void
x2apic_ctl:: write_icr(const value_t icr) noexcept
{ intel_msrs::ia32_x2apic_icr::set(icr); }

void
x2apic_ctl:: write_lvt(const lvt_reg reg, const value_t val) noexcept
{
    switch (reg) {
        case perf: intel_msrs::ia32_x2apic_lvt_pmi::set(val); return;
        case cmci: intel_msrs::ia32_x2apic_lvt_cmci::set(val); return;
        case timer: intel_msrs::ia32_x2apic_lvt_timer::set(val); return;
        case lint0: intel_msrs::ia32_x2apic_lvt_lint0::set(val); return;
        case lint1: intel_msrs::ia32_x2apic_lvt_lint1::set(val); return;
        case error: intel_msrs::ia32_x2apic_lvt_error::set(val); return;
        case thermal: intel_msrs::ia32_x2apic_lvt_thermal::set(val); return;

        default:
            bferror_info(0, "invalid lvt_reg");
            return;
    }
}

void
x2apic_ctl:: write_init_count(const value_t count) noexcept
{ intel_msrs::ia32_x2apic_init_count::set(count); }

void
x2apic_ctl:: write_div_config(const value_t config) noexcept
{ intel_msrs::ia32_x2apic_div_conf::set(config); }


///
/// Send a self-ipi
///
/// A self-ipi is a self-targeted, edge-triggered, fixed interrupt
/// with the specified vector.
///
/// @param vec - the vector of the self-ipi
///
void
x2apic_ctl:: write_self_ipi(const vector_t vec) noexcept
{ intel_msrs::ia32_x2apic_self_ipi::vector::set(vec); }

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
bool
x2apic_ctl::level_triggered(const vector_t vec) noexcept
{
    auto reg = (vec & 0xE0) >> 5;
    auto bit = 1ULL << (vec & 0x1F);

    switch (reg) {
        case 0: return intel_msrs::ia32_x2apic_tmr0::get() & bit;
        case 1: return intel_msrs::ia32_x2apic_tmr1::get() & bit;
        case 2: return intel_msrs::ia32_x2apic_tmr2::get() & bit;
        case 3: return intel_msrs::ia32_x2apic_tmr3::get() & bit;
        case 4: return intel_msrs::ia32_x2apic_tmr4::get() & bit;
        case 5: return intel_msrs::ia32_x2apic_tmr5::get() & bit;
        case 6: return intel_msrs::ia32_x2apic_tmr6::get() & bit;
        case 7: return intel_msrs::ia32_x2apic_tmr7::get() & bit;

        default:
            bferror_info(0, "invalid vector_t");
            return false;
    }
}

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
bool
x2apic_ctl::in_service(const vector_t vec) noexcept
{
    auto reg = (vec & 0xE0) >> 5;
    auto bit = 1ULL << (vec & 0x1F);

    switch (reg) {
        case 0: return intel_msrs::ia32_x2apic_isr0::get() & bit;
        case 1: return intel_msrs::ia32_x2apic_isr1::get() & bit;
        case 2: return intel_msrs::ia32_x2apic_isr2::get() & bit;
        case 3: return intel_msrs::ia32_x2apic_isr3::get() & bit;
        case 4: return intel_msrs::ia32_x2apic_isr4::get() & bit;
        case 5: return intel_msrs::ia32_x2apic_isr5::get() & bit;
        case 6: return intel_msrs::ia32_x2apic_isr6::get() & bit;
        case 7: return intel_msrs::ia32_x2apic_isr7::get() & bit;

        default:
            bferror_info(0, "invalid vector_t");
            return false;
    }
}

}
}
