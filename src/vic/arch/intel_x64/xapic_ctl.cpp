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
#include <atomic>
#include <vic/arch/intel_x64/xapic_ctl.h>

namespace eapis
{
namespace intel_x64
{

using value_t = xapic_ctl::value_t;

int
xapic_ctl::check_gpa_op(const gpa_t addr, const reg_op op) noexcept
{
    auto reg = xapic::reg_set.find((addr & 0xFF0U) >> 4);

    if (reg != xapic::reg_set.end()) {
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
xapic_ctl::check_msr_op(const field_t msr, const reg_op op) noexcept
{
    if (msr < intel_lapic::msr_start_reg || msr > intel_lapic::msr_end_reg) {
        return -1;
    }
    auto reg = xapic::reg_set.find(msr & 0xFFU);

    if (reg != xapic::reg_set.end()) {
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
xapic_ctl::read_register(const uint32_t offset) noexcept
{ return m_apic_page[offset << 2]; }

void
xapic_ctl:: write_register(const uint32_t offset, const value_t val) noexcept
{ m_apic_page[offset << 2] = gsl::narrow_cast<uint32_t>(val); }

value_t
xapic_ctl::read_id() noexcept
{ return read_register(xapic::regs::id.offset); }

value_t
xapic_ctl::read_version() noexcept
{ return read_register(xapic::regs::version.offset); }

value_t
xapic_ctl::read_tpr() noexcept
{ return read_register(xapic::regs::tpr.offset); }

value_t
xapic_ctl::read_ldr() noexcept
{ return read_register(xapic::regs::ldr.offset); }

value_t
xapic_ctl::read_svr() noexcept
{ return read_register(xapic::regs::sivr.offset); }

value_t
xapic_ctl::read_icr() noexcept
{
    value_t low = read_register(xapic::regs::icr_low.offset);
    value_t high = read_register(xapic::regs::icr_high.offset);
    return (high << 32) | low;
}

value_t
xapic_ctl::read_isr(const index idx) noexcept
{
    auto offset = xapic::regs::isr0.offset | idx;
    return read_register(offset);
}

value_t
xapic_ctl::read_tmr(const index idx) noexcept
{
    auto offset = xapic::regs::tmr0.offset | idx;
    return read_register(offset);
}

value_t
xapic_ctl::read_irr(const index idx) noexcept
{
    auto offset = xapic::regs::irr0.offset | idx;
    return read_register(offset);
}

value_t
xapic_ctl::read_lvt(const lvt_reg reg) noexcept
{
    switch (reg) {
        case cmci:
            return read_register(xapic::regs::lvt_cmci.offset);
        case timer:
            return read_register(xapic::regs::lvt_timer.offset);
        case thermal:
            return read_register(xapic::regs::lvt_thermal.offset);
        case perf:
            return read_register(xapic::regs::lvt_perf.offset);
        case lint0:
            return read_register(xapic::regs::lvt_lint0.offset);
        case lint1:
            return read_register(xapic::regs::lvt_lint1.offset);
        case error:
            return read_register(xapic::regs::lvt_error.offset);

        default:
            bferror_info(0, "invalid lvt_reg");
            return 0;
    }
}

value_t
xapic_ctl::read_count(const count_reg reg) noexcept
{
    switch (reg) {
        case initial:
            return read_register(xapic::regs::init_count.offset);
        case current:
            return read_register(xapic::regs::cur_count.offset);

        default:
            bferror_info(0, "invalid count_reg");
            return 0;
    }
}

value_t
xapic_ctl::read_div_config() noexcept
{ return read_register(xapic::regs::div_conf.offset); }

void
xapic_ctl:: write_eoi() noexcept
{ write_register(xapic::regs::eoi.offset, 0x0ULL); }

void
xapic_ctl:: write_tpr(const value_t tpr) noexcept
{ write_register(xapic::regs::tpr.offset, tpr); }

void
xapic_ctl:: write_svr(const value_t svr) noexcept
{ write_register(xapic::regs::sivr.offset, svr); }

void
xapic_ctl:: write_icr(const value_t icr) noexcept
{
    value_t low = icr & 0x00000000FFFFFFFFULL;
    value_t high = (icr & 0xFFFFFFFF00000000ULL) >> 32;
    write_register(xapic::regs::icr_high.offset, high);
    ::intel_x64::fence::sfence();
    write_register(xapic::regs::icr_low.offset, low);
}

void
xapic_ctl:: write_lvt(const lvt_reg reg, const value_t val) noexcept
{
    switch (reg) {
        case cmci:
            write_register(xapic::regs::lvt_cmci.offset, val);
            return;
        case timer:
            write_register(xapic::regs::lvt_timer.offset, val);
            return;
        case thermal:
            write_register(xapic::regs::lvt_thermal.offset, val);
            return;
        case perf:
            write_register(xapic::regs::lvt_perf.offset, val);
            return;
        case lint0:
            write_register(xapic::regs::lvt_lint0.offset, val);
            return;
        case lint1:
            write_register(xapic::regs::lvt_lint1.offset, val);
            return;
        case error:
            write_register(xapic::regs::lvt_error.offset, val);
            return;

        default:
            bferror_info(0, "invalid lvt_reg");
            return;
    }
}

void
xapic_ctl:: write_init_count(const value_t count) noexcept
{ write_register(xapic::regs::init_count.offset, count); }

void
xapic_ctl:: write_div_config(const value_t config) noexcept
{ write_register(xapic::regs::div_conf.offset, config); }

void
xapic_ctl:: write_self_ipi(const vector_t vec) noexcept
{
    value_t val = 0x0ULL | (vec & 0xFFULL) | 0x44000ULL;
    write_icr(val);
}

bool
xapic_ctl::level_triggered(const vector_t vec) noexcept
{
    auto reg = (vec & 0xE0) >> 5;
    auto bit = 1ULL << (vec & 0x1F);

    switch (reg) {
        case 0: return read_register(xapic::regs::tmr0.offset) & bit;
        case 1: return read_register(xapic::regs::tmr1.offset) & bit;
        case 2: return read_register(xapic::regs::tmr2.offset) & bit;
        case 3: return read_register(xapic::regs::tmr3.offset) & bit;
        case 4: return read_register(xapic::regs::tmr4.offset) & bit;
        case 5: return read_register(xapic::regs::tmr5.offset) & bit;
        case 6: return read_register(xapic::regs::tmr6.offset) & bit;
        case 7: return read_register(xapic::regs::tmr7.offset) & bit;

        default:
            bferror_info(0, "invalid vector_t");
            return false;
    }
}

bool
xapic_ctl::in_service(const vector_t vec) noexcept
{
    auto reg = (vec & 0xE0) >> 5;
    auto bit = 1ULL << (vec & 0x1F);

    switch (reg) {
        case 0: return read_register(xapic::regs::isr0.offset) & bit;
        case 1: return read_register(xapic::regs::isr1.offset) & bit;
        case 2: return read_register(xapic::regs::isr2.offset) & bit;
        case 3: return read_register(xapic::regs::isr3.offset) & bit;
        case 4: return read_register(xapic::regs::isr4.offset) & bit;
        case 5: return read_register(xapic::regs::isr5.offset) & bit;
        case 6: return read_register(xapic::regs::isr6.offset) & bit;
        case 7: return read_register(xapic::regs::isr7.offset) & bit;

        default:
            bferror_info(0, "invalid vector_t");
            return false;
    }
}

}
}
