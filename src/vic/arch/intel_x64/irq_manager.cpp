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

#include <bfthreadcontext.h>
#include <vic/arch/intel_x64/isr.h>
#include <vic/arch/intel_x64/irq_manager.h>

/// ---------------------------------------------------------------------------
/// Namespace aliases
/// ---------------------------------------------------------------------------

namespace apic_state = ::intel_x64::msrs::ia32_apic_base::state;
namespace intel_msrs = ::intel_x64::msrs;
namespace intel_vmcs = ::intel_x64::vmcs;

namespace guest_irq_flag = intel_vmcs::guest_rflags::interrupt_enable_flag;
namespace guest_irq_state = intel_vmcs::guest_interruptibility_state;
namespace guest_act_state = intel_vmcs::guest_activity_state;

namespace exit_irq_info = intel_vmcs::vm_exit_interruption_information;
namespace entry_irq_info = intel_vmcs::vm_entry_interruption_information;
namespace irq_type = entry_irq_info::interruption_type;

/// ---------------------------------------------------------------------------
/// Type aliases
/// ---------------------------------------------------------------------------

using x2apic_ctl_t = eapis::intel_x64::x2apic_ctl;
using wrmsr_hdlr_t = eapis::intel_x64::msrs::wrmsr_handler_delegate_t;

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

static bool
handle_wrmsr_eoi(
    gsl::not_null<irq_manager::vmcs_t *> vmcs,
    irq_manager::msrs_t::info_t &info)
{
    bfignored(vmcs);
    info.ignore_write = true;
    info.ignore_advance = false;
    return true;
}

irq_manager::irq_manager(
    gsl::not_null<exit_handler_t *> exit_handler,
    gsl::not_null<vmcs_t *> vmcs,
    gsl::not_null<msrs_t *> msrs)
    : m_exit_handler{exit_handler}, m_vmcs{vmcs}, m_msrs{msrs}
{
    init_apic_ctl();
    init_host_idt();
    init_handlers();
    init_save_state();

    ::x64::rflags::interrupt_enable_flag::disable();
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
    m_ist1 = std::make_unique<gsl::byte[]>(STACK_SIZE * 2);
    m_exit_handler->host_tss()->ist1 = setup_stack(m_ist1.get());

    const auto selector = 0x8U;
    set_default_isrs(m_exit_handler->host_idt(), selector);
}

void
irq_manager::init_apic_ctl()
{
    if (!intel_lapic::is_present()) {
        throw std::runtime_error("lapic not present");
    }

    if (intel_x2apic::supported()) {
        init_x2apic_ctl();
        return;
    }

    throw std::runtime_error("x2apic not supported");
}

void
irq_manager::init_x2apic_ctl()
{
    switch (apic_state::get()) {
        case apic_state::x2apic:
            break;

        case apic_state::disabled:
        case apic_state::invalid:
        case apic_state::xapic:
        default:
            bferror_info(1, "Invalid state for x2apic init");
            apic_state::dump(0);
            throw std::exception();
    }

    m_lapic_ctl = std::make_unique<x2apic_ctl_t>();
}

void
irq_manager::init_handlers()
{
    m_irqwin = std::make_unique<irq_window_t>(m_exit_handler);
    m_extirq = std::make_unique<irq_t>(m_exit_handler);

    for (auto v = 32; v < 256; v++) {
        auto hdlr = hdlr_t::create<irqmgr_t, &irqmgr_t::handle_extirq>(this);
        m_extirq->add_handler(v, std::move(hdlr));
    }

    auto hdlr = hdlr_t::create<irqmgr_t, &irqmgr_t::handle_irqwin>(this);
    m_irqwin->add_handler(std::move(hdlr));

    m_msrs->add_wrmsr_handler(
        intel_msrs::ia32_x2apic_eoi::addr,
        wrmsr_hdlr_t::create<handle_wrmsr_eoi>()
    );
    m_msrs->trap_on_wrmsr_access(intel_msrs::ia32_x2apic_eoi::addr);

    m_extirq->trap();
}

void
irq_manager::inject_irq(vector_t v)
{
    const auto type = irq_type::external_interrupt;
    auto info = 0U;

    info = entry_irq_info::vector::set(info, v);
    info = entry_irq_info::interruption_type::set(info, type);
    info = entry_irq_info::valid_bit::enable(info);

    entry_irq_info::set(info);
    entry_irq_info::dump(1);
}

bool
irq_manager::handle_extirq(gsl::not_null<vmcs_t *> vmcs)
{
    auto v = exit_irq_info::vector::get();
    bfdebug_nhex(1, "extirq", v);
    handle_irq(v);
    return true;
}

bool
irq_manager::handle_irqwin(gsl::not_null<vmcs_t *> vmcs)
{
    auto v = m_virr.front();
    bfdebug_nhex(1, "irqwin opened", v);
    inject_irq(v);
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
