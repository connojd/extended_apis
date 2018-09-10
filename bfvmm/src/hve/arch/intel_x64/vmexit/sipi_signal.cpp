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
    gsl::not_null<apis *> apis
) :
    m_ia32_vmx_cr0_fixed0{apis->ia32_vmx_cr0_fixed0()},
    m_ia32_vmx_cr4_fixed0{apis->ia32_vmx_cr4_fixed0()}
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
    using namespace vmcs_n::vm_entry_controls;
    bfignored(vmcs);

    // .........................................................................
    // Ignore SIPI - SIPI
    // .........................................................................

    // The Intel spec states that more than one SIPI should be sent
    // to each AP in the event that the first AP is ignored. The problem
    // with this approach is that it is possible for the exit handler to
    // see both SIPIs (i.e. the second sipi is not actually dropped by
    // the CPU). If this happens, we need to emulate this drop our selves
    //

    if (vmcs_n::guest_activity_state::get() == active) {
        return true;
    }

    // .........................................................................
    // INIT
    // .........................................................................

    // We don't execute the init process in INIT due to a race between the
    // INIT - SIPI - SIPI process with the operating system, which only gives
    // a 10us delay on modern hardware. To prevent this from being an issue,
    // while also preventing the need for complicated synchronization logic,
    // we perform the INIT process during the SIPI process itself.
    //
    // The goal or our INIT logic is to mimic the same logic documented in the
    // SDM, so as a result, the following code is in the same order as the SDM
    // so that it matches.
    //

    ia_32e_mode_guest::disable();

    // TODO:
    //
    // - Currently, there are several registers that the VMCS does not control
    //   and that we are not saving in our save state that we are not resetting
    //   here. For completness, we should find a way to reset all of the
    //   registers outlined by the SDM. These registers include:
    //   - CR2
    //   - x87 FPU Control Word
    //   - x87 FPU Status Word
    //   - x87 FPU Tag Word
    //   - x87 FPU Data Operand
    //   - dr0, dr1, dr2, dr3
    //   - dr6
    //   = IA32_XSS
    //   - BNDCFGU
    //   - BND0-BND3
    //   - IA32_BNDCFGS
    //
    // - Currently, we don't set the Extended Model Value in EDX, whish is
    //   stated by the SDM. We use 0x600, which seems to work fine, but
    //   at some point, we should fill in the proper value
    //

    vmcs_n::guest_rflags::set(0x00000002);
    vmcs->save_state()->rip = 0x0000FFF0;

    vmcs_n::guest_cr0::set(0x60000010 | m_ia32_vmx_cr0_fixed0);
    vmcs_n::guest_cr3::set(0);
    vmcs_n::guest_cr4::set(0x00000000 | m_ia32_vmx_cr4_fixed0);

    vmcs_n::cr0_read_shadow::set(0x60000010);
    vmcs_n::cr4_read_shadow::set(0);

    vmcs_n::guest_cs_selector::set(0xF000);
    vmcs_n::guest_cs_base::set(0xFFFF0000);
    vmcs_n::guest_cs_limit::set(0xFFFF);
    vmcs_n::guest_cs_access_rights::set(0x9B);

    vmcs_n::guest_ss_selector::set(0);
    vmcs_n::guest_ss_base::set(0);
    vmcs_n::guest_ss_limit::set(0xFFFF);
    vmcs_n::guest_ss_access_rights::set(0x93);

    vmcs_n::guest_ds_selector::set(0);
    vmcs_n::guest_ds_base::set(0);
    vmcs_n::guest_ds_limit::set(0xFFFF);
    vmcs_n::guest_ds_access_rights::set(0x93);

    vmcs_n::guest_es_selector::set(0);
    vmcs_n::guest_es_base::set(0);
    vmcs_n::guest_es_limit::set(0xFFFF);
    vmcs_n::guest_es_access_rights::set(0x93);

    vmcs_n::guest_fs_selector::set(0);
    vmcs_n::guest_fs_base::set(0);
    vmcs_n::guest_fs_limit::set(0xFFFF);
    vmcs_n::guest_fs_access_rights::set(0x93);

    vmcs_n::guest_gs_selector::set(0);
    vmcs_n::guest_gs_base::set(0);
    vmcs_n::guest_gs_limit::set(0xFFFF);
    vmcs_n::guest_gs_access_rights::set(0x93);

    vmcs->save_state()->rdx = 0x00000600;
    vmcs->save_state()->rax = 0;
    vmcs->save_state()->rbx = 0;
    vmcs->save_state()->rcx = 0;
    vmcs->save_state()->rsi = 0;
    vmcs->save_state()->rdi = 0;
    vmcs->save_state()->rbp = 0;
    vmcs->save_state()->rsp = 0;

    vmcs_n::guest_gdtr_base::set(0);
    vmcs_n::guest_gdtr_limit::set(0xFFFF);

    vmcs_n::guest_idtr_base::set(0);
    vmcs_n::guest_idtr_limit::set(0xFFFF);

    vmcs_n::guest_ldtr_selector::set(0);
    vmcs_n::guest_ldtr_base::set(0);
    vmcs_n::guest_ldtr_limit::set(0xFFFF);
    vmcs_n::guest_ldtr_access_rights::set(0x82);

    vmcs_n::guest_tr_selector::set(0);
    vmcs_n::guest_tr_base::set(0);
    vmcs_n::guest_tr_limit::set(0xFFFF);
    vmcs_n::guest_tr_access_rights::set(0x8B);

    vmcs_n::guest_dr7::set(0x00000400);

    vmcs->save_state()->r08 = 0;
    vmcs->save_state()->r09 = 0;
    vmcs->save_state()->r10 = 0;
    vmcs->save_state()->r11 = 0;
    vmcs->save_state()->r12 = 0;
    vmcs->save_state()->r13 = 0;
    vmcs->save_state()->r14 = 0;
    vmcs->save_state()->r15 = 0;

    vmcs_n::guest_ia32_efer::set(0);
    vmcs_n::guest_fs_base::set(0);
    vmcs_n::guest_gs_base::set(0);

    // .........................................................................
    // SIPI
    // .........................................................................

    // This is where we actually execute the SIPI logic. Most of the code here
    // overwrites some of the logic in the INIT code above, but we wanted this
    // to be easy to read and self documenting, and the extra time it takes
    // to redo some of these registers is not important.
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
        vmcs_n::exit_qualification::sipi::vector::get() << 8;

    auto vector_cs_base =
        vmcs_n::exit_qualification::sipi::vector::get() << 12;

    vmcs_n::guest_cs_selector::set(vector_cs_selector);
    vmcs_n::guest_cs_base::set(vector_cs_base);
    vmcs_n::guest_cs_limit::set(0xFFFF);
    vmcs_n::guest_cs_access_rights::set(0x9B);

    vmcs->save_state()->rip = 0;

    vmcs_n::guest_activity_state::set(
        vmcs_n::guest_activity_state::active
    );

    return true;
}

}
}
