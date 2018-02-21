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

#include <vic/arch/intel_x64/base.h>
#include <vic/arch/intel_x64/isr.h>
#include <vic/arch/intel_x64/interrupt_manager.h>

namespace eapis
{
namespace intel_x64
{

static bool
handle_wrmsr_eoi(gsl::not_null<vmcs_t *> vmcs, msrs::info_t &info)
{
    bfignored(vmcs);
    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

interrupt_manager::interrupt_manager(
    gsl::not_null<exit_handler_t *> exit_handler,
    gsl::not_null<vmcs_t *> vmcs,
    gsl::not_null<msrs *> msrs)
:
    m_exit_handler{exit_handler}, m_vmcs{vmcs}, m_msrs{msrs}
{
    init_save_state();
    init_host_idt();
    init_apic_ctl();
    init_handlers();

    ::x64::rflags::interrupt_enable_flag::disable();
}

void
interrupt_manager::init_save_state()
{
    auto state_ptr = m_vmcs->save_state();
    state_ptr->interrupt_manager_ptr = reinterpret_cast<uintptr_t>(this);
}

void
interrupt_manager::init_host_idt()
{
    m_ist1 = std::make_unique<gsl::byte[]>(STACK_SIZE * 2);
    m_exit_handler->host_tss()->ist1 = setup_stack(m_ist1.get());

    const auto selector = 0x8U;
    set_default_isrs(m_exit_handler->host_idt(), selector);
}

void
interrupt_manager::init_apic_ctl()
{
    if (!::intel_x64::lapic::is_present()) {
        throw std::runtime_error("lapic not present");
    }

    if (::intel_x64::x2apic::supported()) {
        init_x2apic_ctl();
        return;
    }

    throw std::runtime_error("x2apic not supported");
}

void
interrupt_manager::init_x2apic_ctl()
{
    switch (::intel_x64::msrs::ia32_apic_base::state::get()) {
        case ::intel_x64::msrs::ia32_apic_base::state::x2apic:
            break;

        case ::intel_x64::msrs::ia32_apic_base::state::disabled:
        case ::intel_x64::msrs::ia32_apic_base::state::invalid:
        case ::intel_x64::msrs::ia32_apic_base::state::xapic:
        default:
            bferror_info(1, "Invalid state for x2apic init");
            ::intel_x64::msrs::ia32_apic_base::state::dump(1);
            throw std::exception();
    }

    m_lapic_ctl = std::make_unique<x2apic_ctl>();
}

void
interrupt_manager::init_external_interrupt_handlers()
{
    using int_handler_t =
        delegate<bool(gsl::not_null<vmcs_t*>, external_interrupt::info_t&)>;

    m_external_interrupt = std::make_unique<external_interrupt>(m_exit_handler);

    for (auto v = 32; v < 256; ++v) {
        auto handler = int_handler_t::create<
            interrupt_manager,
            &interrupt_manager::handle_external_interrupt>(this);
        m_external_interrupt->add_handler(v, std::move(handler));
    }

    m_external_interrupt->enable_trapping();
}

void
interrupt_manager::init_interrupt_window_handler()
{
    m_interrupt_window = std::make_unique<interrupt_window>(m_exit_handler);
}

void
interrupt_manager::init_x2apic_handlers()
{
    m_msrs->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_x2apic_eoi::addr,
        msrs::handler_delegate_t::create<handle_wrmsr_eoi>()
    );

    m_msrs->trap_on_wrmsr_access(::intel_x64::msrs::ia32_x2apic_eoi::addr);
}

void
interrupt_manager::init_handlers()
{
    init_external_interrupt_handlers();
    init_interrupt_window_handler();
    init_x2apic_handlers();
}

bool
interrupt_manager::handle_external_interrupt(
    gsl::not_null<vmcs_t *> vmcs,
    external_interrupt::info_t &info)
{
    bfdebug_nhex(1, "interrupt", info.vector);
    handle_interrupt(info.vector);
    return true;
}

void
interrupt_manager::handle_interrupt(vmcs_n::value_type vector)
{
    m_lapic_ctl->write_eoi();
    m_interrupt_window->queue_interrupt(vector);
}

}
}
