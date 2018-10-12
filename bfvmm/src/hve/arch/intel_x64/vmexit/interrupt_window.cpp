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

#include <hve/arch/intel_x64/vcpu.h>

namespace eapis::intel_x64
{

interrupt_window_handler::interrupt_window_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::interrupt_window,
        ::handler_delegate_t::create<interrupt_window_handler, &interrupt_window_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
interrupt_window_handler::queue_external_interrupt(uint64_t vector)
{
    if (this->is_open() && m_interrupt_queue.empty()) {
        this->inject(vector);
    }
    else {
        this->enable_exiting();
        m_interrupt_queue.push(vector);
    }
}


// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
interrupt_window_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);
    this->inject(m_interrupt_queue.pop());

    if (m_interrupt_queue.empty()) {
        this->disable_exiting();
    }

    return true;
}

// -----------------------------------------------------------------------------
// Private
// -----------------------------------------------------------------------------

void
interrupt_window_handler::enable_exiting()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::interrupt_window_exiting::enable();
}

void
interrupt_window_handler::disable_exiting()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::interrupt_window_exiting::disable();
}

bool
interrupt_window_handler::is_open()
{
    using namespace vmcs_n;

    if (guest_rflags::interrupt_enable_flag::is_disabled()) {
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

    const auto state = guest_interruptibility_state::get();

    if (guest_interruptibility_state::blocking_by_sti::is_enabled(state)) {
        return false;
    }

    if (guest_interruptibility_state::blocking_by_mov_ss::is_enabled(state)) {
        return false;
    }

    return true;
}

void
interrupt_window_handler::inject(uint64_t vector)
{
    uint64_t info = 0;
    using namespace vmcs_n::vm_entry_interruption_information;

    vector::set(info, vector);
    interruption_type::set(info, interruption_type::external_interrupt);
    valid_bit::enable(info);

    vmcs_n::vm_entry_interruption_information::set(info);
}

}
