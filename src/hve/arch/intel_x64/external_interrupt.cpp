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

#include <hve/arch/intel_x64/external_interrupt.h>

namespace eapis
{
namespace intel_x64
{

static external_interrupt::info_t
parse_info(gsl::not_null<vmcs_t *> vmcs)
{ return { vmcs_n::vm_exit_interruption_information::vector::get() }; }

external_interrupt::external_interrupt(
    gsl::not_null<exit_handler_t *> exit_handler
) :
    m_exit_handler{exit_handler}
{
    m_exit_handler->add_handler(
        vmcs_n::exit_reason::basic_exit_reason::external_interrupt,
        handler_delegate_t::create<
            external_interrupt,
            &external_interrupt::handle
        >(this)
    );
}

external_interrupt::~external_interrupt()
{
    if (!ndebug && this->is_logging_enabled()) {
        dump_log();
    }
}

void
external_interrupt::add_handler(vmcs_n::value_type vector, handler_t &&d)
{ m_handlers[vector].push_front(std::move(d)); }

void
external_interrupt::enable_trapping() const
{
    vmcs_n::vm_exit_controls::acknowledge_interrupt_on_exit::enable();
    vmcs_n::pin_based_vm_execution_controls::external_interrupt_exiting::enable();
}

bool
external_interrupt::handle(gsl::not_null<vmcs_t *> vmcs)
{
    auto info = parse_info(vmcs);

    if (!ndebug && this->is_logging_enabled()) {
        add_record(m_log, { info.vector });
    }

    for (const auto &d : m_handlers[info.vector]) {
        if (d(vmcs, info)) {
            return true;
        }
    }

    return false;
}

void
external_interrupt::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "external interrupt log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_subnhex(0, "vector", record.vector, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

}
}
