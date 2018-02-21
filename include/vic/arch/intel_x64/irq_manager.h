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

#ifndef IRQ_MANAGER_INTEL_X64_EAPIS_H
#define IRQ_MANAGER_INTEL_X64_EAPIS_H

#include <deque>

#include <bfgsl.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>

#include "lapic_ctl.h"
#include "xapic_ctl.h"
#include "x2apic_ctl.h"

#include "../../../hve/arch/intel_x64/irq.h"
#include "../../../hve/arch/intel_x64/irq_window.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_VIC
#ifdef SHARED_EAPIS_VIC
#define EXPORT_EAPIS_VIC EXPORT_SYM
#else
#define EXPORT_EAPIS_VIC IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_VIC
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class EXPORT_EAPIS_VIC irq_manager
{
public:

    using irqmgr_t = eapis::intel_x64::irq_manager;
    using vmcs_t = bfvmm::intel_x64::vmcs;
    using exit_handler_t = bfvmm::intel_x64::exit_handler;
    using lapic_ctl_t = eapis::intel_x64::lapic_ctl;
    using vector_t = lapic_ctl_t::vector_t;
    using hdlr_t = delegate<bool(gsl::not_null<vmcs_t *>)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    irq_manager(
        gsl::not_null<exit_handler_t *> exit_handler,
        gsl::not_null<vmcs_t *> vmcs
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~irq_manager() = default;

    /// Handle interrupt-window exit
    ///
    /// @expects
    /// @ensures
    ///
    /// If interrupt-window exiting is enabled, an exit occurs on any
    /// instruction boundary at which the guest is interruptible i.e
    ///
    /// guest.rflags.if = 1 &&
    /// interruptibility_state.blocking_by_sti = 0 &&
    /// interruptibility_state.blocking_by_mov_ss = 0 &&
    ///
    bool handle_irqwin(gsl::not_null<vmcs_t *> vmcs);

    /// Handle external-interrupt exit
    ///
    /// @expects
    /// @ensures
    ///
    /// Handler for external-interrupt exits
    ///
    /// @param vmcs the vmcs for this exit reason
    ///
    bool handle_extirq(gsl::not_null<vmcs_t *> vmcs);

    /// Handle physical interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// Handle a "physical interrupt", which may come from the host
    /// IDT (when in VMX-root) or from a VM-exit (when in VMX-nonroot
    /// and external-interrupt-exiting is enabled).
    ///
    void handle_irq(vector_t v);

private:

    /// @cond

    void add_handlers();
    void init_host_idt();
    void init_apic_ctl();
    void init_xapic_ctl();
    void init_x2apic_ctl();
    void init_save_state();
    void inject_irq(vector_t v);

    exit_handler_t *m_exit_handler{nullptr};
    vmcs_t *m_vmcs{nullptr};

    std::unique_ptr<irq> m_extirq{nullptr};
    std::unique_ptr<irq_window> m_irqwin{nullptr};
    std::unique_ptr<lapic_ctl_t> m_lapic_ctl{nullptr};

    std::deque<vector_t> m_virr;

    /// @endcond

public:

    /// @cond

    irq_manager(irq_manager &&) = default;
    irq_manager &operator=(irq_manager &&) = default;

    irq_manager(const irq_manager &) = delete;
    irq_manager &operator=(const irq_manager &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
