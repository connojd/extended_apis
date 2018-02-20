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

#ifndef EXTIRQ_HDLR_INTEL_X64_EAPIS_H
#define EXTIRQ_HDLR_INTEL_X64_EAPIS_H

#include <utility>
#include <unordered_map>

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace eapis
{
namespace intel_x64
{

namespace reason = ::intel_x64::vmcs::exit_reason::basic_exit_reason;

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

///
/// External interrupt handler
///
class EXPORT_EAPIS_HVE irq
{
public:

    using exit_handler_t = bfvmm::intel_x64::exit_handler;
    using vmcs_t = bfvmm::intel_x64::vmcs;
    using handler_t = delegate<bool(gsl::not_null<vmcs_t *>)>;
    using irq_t = eapis::intel_x64::irq;
    using vector_t = uint64_t;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    irq(gsl::not_null<exit_handler_t *> exit_handler);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~irq() = default;

    /// Add handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the interrupt vector to listen to
    /// @param d the handler to call when an exit occurs at vector
    ///
    void add_handler(vector_t vector, handler_t &&d);

    /// Enabl3
    ///
    /// @expects
    /// @ensures
    ///
    /// Enable external-interrupt exiting. This vcpu will exit each time
    /// any interrupt fires during VMX-nonroot operation.
    ///
    void enable();

    /// Disable
    ///
    /// @expects
    /// @ensures
    ///
    /// Disable external-interrupt exiting. This vcpu will not exit if the
    /// vcpu is interrupted during VMX-nonroot.
    ///
    void disable();

    /// Handle
    ///
    /// Invoke the handler listening for irq exits at the
    /// vector in the vmcs exit interruption info field
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs state passed to each handler
    ///
    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @cond

    irq(irq &&) = default;
    irq &operator=(irq &&) = default;

    irq(const irq &) = delete;
    irq &operator=(const irq &) = delete;

    /// @endcond

private:
    exit_handler_t *m_exit_handler;
    std::unordered_map<vector_t, std::list<handler_t>> m_handlers{};
};

} // namespace intel_x64
} // namespace eapis

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
