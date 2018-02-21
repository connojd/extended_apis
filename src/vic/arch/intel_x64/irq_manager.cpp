//
// Bareflank Extended APIs
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

#include <vic/arch/intel_x64/isr.h>
#include <vic/arch/intel_x64/irq_manager.h>

namespace intel_vmcs = ::intel_x64::vmcs;
namespace guest_irq_flag = intel_vmcs::guest_rflags::interrupt_enable_flag;
namespace guest_irq_state = intel_vmcs::guest_interruptibility_state;
namespace guest_act_state = intel_vmcs::guest_activity_state;
namespace exit_irq_info = intel_vmcs::vm_exit_interruption_information;
namespace entry_irq_info = intel_vmcs::vm_entry_interruption_information;

/// ---------------------------------------------------------------------------
/// Helpers
/// ---------------------------------------------------------------------------

static bool
irq_window_open()
{
    if (guest_irq_flag::is_disabled()) {
        return false;
    }

    switch (guest_act_state::get()) {
        case guest_act_state::active:
        case guest_act_state::hlt:
            break;

        case guest_act_state::shutdown:
        case guest_act_state::wait_for_sipi:
        default:
            return false;
    }

    const auto irq_state = guest_irq_state::get();

    if (guest_irq_state::blocking_by_sti::is_enabled(irq_state)) {
        return false;
    }

    if (guest_irq_state::blocking_by_mov_ss::is_enabled(irq_state)) {
        return false;
    }

    return true;
}

namespace eapis
{
namespace intel_x64
{

using xapic_ctl_t = eapis::intel_x64::xapic_ctl;
using x2apic_ctl_t = eapis::intel_x64::x2apic_ctl;

irq_manager::irq_manager(
    gsl::not_null<exit_handler_t *> exit_handler,
    gsl::not_null<vmcs_t *> vmcs
) :
    m_exit_handler{exit_handler},
    m_vmcs{vmcs}
{
    init_save_state();
    init_host_idt();
    init_apic_ctl();

    add_handlers();
}

void
irq_manager::init_save_state()
{
    auto state_ptr = m_vmcs->save_state();
    state_ptr->irq_manager_ptr = reinterpret_cast<uintptr_t>(this);
}

void
irq_manager::init_host_idt()
{
    idt::init(m_exit_handler);
}

void
irq_manager::init_apic_ctl()
{
    if (!intel_lapic::is_present()) {
        throw std::runtime_error("lapic not present");
    }

    if (::intel_x64::x2apic::supported()) {
        init_x2apic_ctl();
        return;
    }

    if (::intel_x64::xapic::supported()) {
        init_xapic_ctl();
        return;
    }

    throw std::runtime_error("x2apic and xapic not supported");
}

void
irq_manager::init_xapic_ctl()
{
//    auto base = intel_msrs::ia32_apic_base::apic_base();
//    *map in base*
//    auto virt = g_mm->physint_to_virtptr(base);
}

void
irq_manager::init_x2apic_ctl()
{
    m_lapic_ctl = std::make_unique<x2apic_ctl_t>();
}

void
irq_manager::add_handlers()
{
    m_extirq = std::make_unique<irq>(m_exit_handler);
    m_irqwin = std::make_unique<irq_window>(m_exit_handler);

    for (auto v = 32; v < 256; v++) {
        auto hdlr = hdlr_t::create<irqmgr_t, &irqmgr_t::handle_extirq>(this);
        m_extirq->add_handler(v, std::move(hdlr));
    }

    auto hdlr = hdlr_t::create<irqmgr_t, &irqmgr_t::handle_irqwin>(this);
    m_irqwin->add_handler(std::move(hdlr));

    m_extirq->trap();
}

void
irq_manager::inject_irq(vector_t v)
{
    const auto irq_type = entry_irq_info::interruption_type::external_interrupt;
    auto info = 0U;

    info = entry_irq_info::vector::set(info, v);
    info = entry_irq_info::interruption_type::set(info, irq_type);
    info = entry_irq_info::valid_bit::enable(info);

    entry_irq_info::set(info);
}

bool
irq_manager::handle_extirq(gsl::not_null<vmcs_t *> vmcs)
{
    bfdebug_info(0, "ext");
    handle_irq(exit_irq_info::vector::get());
    return true;
}

bool
irq_manager::handle_irqwin(gsl::not_null<vmcs_t *> vmcs)
{
    inject_irq(m_virr.front());
    m_virr.pop_front();
    m_irqwin->trap(!m_virr.empty());
    return true;
}

void
irq_manager::handle_irq(vector_t v)
{
    m_lapic_ctl->write_eoi();

    if (!irq_window_open()) {
        m_irqwin->trap();
        m_virr.push_back(v);
        return;
    }

    inject_irq(v);
}

}
}
