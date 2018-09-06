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

#include <bfdebug.h>
#include <hve/arch/intel_x64/apis.h>

namespace eapis
{
namespace intel_x64
{

sipi_signal_handler::sipi_signal_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_handler(
        exit_reason::basic_exit_reason::sipi,
        ::handler_delegate_t::create<sipi_signal_handler, &sipi_signal_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
sipi_signal_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n::guest_activity_state;
    bfignored(vmcs);

    // Its possible that more than one SIPI could be received if the
    // first SIPI is not handled by the time the BSP attempts to send
    // the second SIPI. As a result, if we get a second SIPI, we just
    // ignore it.
    //

    // if (vmcs_n::guest_activity_state::get() == active) {
    //     return true;
    // }

    if (first) {
        first = false;
        return true;
    }

    // SIPI Decoding
    //
    // When a SIPI is received, the first instruction executed by the
    // guest is 0x000VV000, with VV being the vector number supplied
    // in the SIPI (hence why the first instruction needs to be page
    // aligned).
    //
    // The segment selector is VV << 8 because we don't need to shift
    // by a full 12 bits since the first 4 bits are the RPL and TI bits.
    //

    auto vector_cs_selector =
        0x9a << 8;

    auto vector_cs_base =
        0x9a << 12;

    vmcs_n::guest_cs_selector::set(vector_cs_selector);
    vmcs_n::guest_cs_base::set(vector_cs_base);
    vmcs_n::guest_cs_limit::set(0xFFFF);
    vmcs_n::guest_cs_access_rights::set(0x9B);

    vmcs->save_state()->rip = 0;
    vmcs_n::guest_activity_state::set(active);

    // bfdebug_info(0, "active state");
    return true;
}

}
}
