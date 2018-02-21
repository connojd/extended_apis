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

namespace eapis
{
namespace intel_x64
{

irq_manager::irq_manager(gsl::not_null<exit_handler_t *> exit_handler) :
    m_exit_handler{exit_handler},
    m_host_tss{exit_handler->host_tss()},
    m_host_idt{exit_handler->host_idt()}
{
    init_lapic_ctl();
    init_host_idt();
}

void
irq_manager::init_host_idt()
{
    idt::init(m_exit_handler);
}

void
irq_manager::init_lapic_ctl()
{
    if (!::intel_x64::lapic::is_present()) {
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

    throw std::runtime_error("x2apic and xapic not support");
}

void
irq_manager::init_xapic_ctl() {}

void
irq_manager::init_x2apic_ctl() {}





}
}
