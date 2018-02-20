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

#include <utility>
#include <hve/arch/intel_x64/irq_window.h>

namespace eapis
{
namespace intel_x64
{

namespace reason = ::intel_x64::vmcs::exit_reason::basic_exit_reason;
namespace pri_ctl = ::intel_x64::vmcs::primary_processor_based_vm_execution_controls;

irq_window::irq_window(gsl::not_null<exit_handler_t *> exit_handler)
    : m_exit_handler{exit_handler}
{
    m_exit_handler->add_handler(
        reason::interrupt_window,
        handler_t::create<irq_window, &irq_window::handle>(this)
    );
}

void
irq_window::add_handler(handler_t &&d)
{
    m_handlers.push_front(std::move(d));
}

void
irq_window::enable()
{
    pri_ctl::interrupt_window_exiting::enable();
}

void
irq_window::disable()
{
    pri_ctl::interrupt_window_exiting::disable();
}

bool
irq_window::handle(gsl::not_null<vmcs_t *> vmcs)
{
    for (const auto &d : m_handlers) {
        if (d(vmcs)) {
            return true;
        }
    }

    return false;
}

} // namespace intel_x64
} // namespace eapis
