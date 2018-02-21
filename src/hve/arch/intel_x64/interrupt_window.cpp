//
// Bareflank Extended APIs
//
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

#include <hve/arch/intel_x64/interrupt_window.h>

namespace eapis
{
namespace intel_x64
{

bool
interrupt_window::is_open()
{
    namespace guest_interrupt_flag = vmcs_n::guest_rflags::interrupt_enable_flag;
    namespace guest_interrupt_state = vmcs_n::guest_interruptibility_state;
    namespace guest_activity_state = vmcs_n::guest_activity_state;

    if (guest_interrupt_flag::is_disabled()) {
        return false;
    }

    switch (guest_activity_state::get()) {
        case guest_activity_state::active:
        case guest_activity_state::hlt:
            break;

        case guest_activity_state::shutdown:
        case guest_activity_state::wait_for_sipi:
        default:
            return false;
    }

    const auto int_state = guest_interrupt_state::get();
    if (guest_interrupt_state::blocking_by_sti::is_enabled(int_state)) {
        return false;
    }

    if (guest_interrupt_state::blocking_by_mov_ss::is_enabled(int_state)) {
        return false;
    }

    return true;
}

interrupt_window::interrupt_window(gsl::not_null<exit_handler_t *> exit_handler)
    : m_exit_handler{exit_handler}
{
    m_exit_handler->add_handler(
        vmcs_n::exit_reason::basic_exit_reason::interrupt_window,
        handler_delegate_t::create<
            interrupt_window,
            &interrupt_window::handle
        >(this)
    );
}

void
interrupt_window::add_handler(handler_delegate_t &&d)
{ m_handlers.push_front(std::move(d)); }

void
interrupt_window::queue_interrupt(vmcs_n::value_type vector)
{
    if (interrupt_window::is_open()) {
        inject_interrupt(vector);
        return;
    }

    enable_trapping();
    m_irr.push_back(vector);
    return;
}

void
interrupt_window::inject_interrupt(vmcs_n::value_type vector) const
{
    namespace entry_interrupt_info = vmcs_n::vm_entry_interruption_information;

    const auto type = entry_interrupt_info::interruption_type::external_interrupt;
    auto info = 0U;

    info = entry_interrupt_info::vector::set(info, vector);
    info = entry_interrupt_info::interruption_type::set(info, type);
    info = entry_interrupt_info::valid_bit::enable(info);

    entry_interrupt_info::set(info);
    entry_interrupt_info::dump(1);
}

void
interrupt_window::enable_trapping() const
{
    using namespace vmcs_n::primary_processor_based_vm_execution_controls;
    interrupt_window_exiting::enable();
}

void
interrupt_window::disable_trapping() const
{
    using namespace vmcs_n::primary_processor_based_vm_execution_controls;
    interrupt_window_exiting::disable();
}

bool
interrupt_window::handle(gsl::not_null<vmcs_t *> vmcs)
{
    auto vector = m_irr.front();
    inject_interrupt(vector);
    m_irr.pop_front();

    if (!m_irr.empty()) {
        enable_trapping();
        for (const auto &d : m_handlers) {
            if (d(vmcs)) {
                return true;
            }
        }

        return true;
    }

    disable_trapping();

    for (const auto &d : m_handlers) {
        if (d(vmcs)) {
            return true;
        }
    }

    return true;
}

}
}
