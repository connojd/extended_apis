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

#ifndef INTERRUPT_MANAGER_INTEL_X64_EAPIS_H
#define INTERRUPT_MANAGER_INTEL_X64_EAPIS_H

#include <deque>

#include "../../../hve/arch/intel_x64/rdmsr.h"
#include "../../../hve/arch/intel_x64/wrmsr.h"
#include "../../../hve/arch/intel_x64/interrupt_window.h"
#include "../../../hve/arch/intel_x64/external_interrupt.h"

#include "base.h"
#include "phys_lapic.h"
#include "phys_x2apic.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

///
/// Interrupt Manager
///
class EXPORT_EAPIS_VIC interrupt_manager
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    interrupt_manager(
        gsl::not_null<exit_handler_t *> exit_handler,
        gsl::not_null<vmcs_t *> vmcs,
        gsl::not_null<rdmsr *> rdmsr,
        gsl::not_null<wrmsr *> wrmsr
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~interrupt_manager() = default;

    /// Handle external-interrupt exit
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs for this exit reason
    /// @param info the info for this exit reason
    ///
    bool handle_external_interrupt(
        gsl::not_null<vmcs_t *> vmcs,
        external_interrupt::info_t &info
    );

    /// Handle interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector at which the interrupt occured
    ///
    void handle_interrupt(vmcs_n::value_type vector);

private:

    /// @cond

    void init_host_idt();
    void init_phys_lapic();
    void init_phys_x2apic();
    void init_save_state();

    void init_external_interrupt_handlers();
    void init_interrupt_window_handler();
    void init_x2apic_handlers();
    void init_handlers();

    exit_handler_t *m_exit_handler{nullptr};
    vmcs_t *m_vmcs{nullptr};
    rdmsr *m_rdmsr{nullptr};
    wrmsr *m_wrmsr{nullptr};

    std::unique_ptr<external_interrupt> m_external_interrupt{nullptr};
    std::unique_ptr<interrupt_window> m_interrupt_window{nullptr};
    std::unique_ptr<phys_lapic> m_phys_lapic{nullptr};

    // The interrupt_manager owns the ist, thus once *this is destroyed,
    // exceptions will have an invalid stack to work off of
    std::unique_ptr<gsl::byte[]> m_ist1{nullptr};

    /// @endcond

public:

    /// @cond

    interrupt_manager(interrupt_manager &&) = default;
    interrupt_manager &operator=(interrupt_manager &&) = default;

    interrupt_manager(const interrupt_manager &) = delete;
    interrupt_manager &operator=(const interrupt_manager &) = delete;

    /// @endcond
};

}
}

#endif
