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

#include <bfgsl.h>

#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>

#include "lapic_ctl.h"
#include "xapic_ctl.h"
#include "x2apic_ctl.h"

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

    using host_tss_t = bfvmm::x64::tss;
    using host_idt_t = bfvmm::x64::idt;
    using vmcs_t = bfvmm::intel_x64::vmcs;
    using exit_handler_t = bfvmm::intel_x64::exit_handler;

    using lapic_ctl_t = eapis::intel_x64::lapic_ctl;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    irq_manager(gsl::not_null<exit_handler_t *> exit_handler);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~irq_manager();

private:

    void init_lapic_ctl();
    void init_xapic_ctl();
    void init_x2apic_ctl();
    void init_host_idt();

    exit_handler_t *m_exit_handler{nullptr};
    host_tss_t *m_host_tss{nullptr};
    host_idt_t *m_host_idt{nullptr};

    std::unique_ptr<lapic_ctl_t> m_lapic_ctl{nullptr};

//    std::unique_ptr<uint8_t[]> m_msr_bitmap;
//    gsl::span<uint8_t> m_msr_bitmap_view;

//    std::unordered_map<msr_t, std::list<rdmsr_handler_delegate_t>> m_rdmsr_handlers;
//    std::unordered_map<msr_t, std::list<wrmsr_handler_delegate_t>> m_wrmsr_handlers;

//    std::unordered_map<msr_t, uint64_t> m_rdmsr_log;
//    std::unordered_map<msr_t, uint64_t> m_wrmsr_log;

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
