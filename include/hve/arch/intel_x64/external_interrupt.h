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

#ifndef EXTERNAL_INTERRUPT_INTEL_X64_EAPIS_H
#define EXTERNAL_INTERRUPT_INTEL_X64_EAPIS_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class EXPORT_EAPIS_HVE external_interrupt : public base
{
public:

    struct info_t {
        uint64_t vector;
    };

    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    external_interrupt(gsl::not_null<exit_handler_t *> exit_handler);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~external_interrupt() final;

    /// Add handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param v the external-interrupt vector to listen to
    /// @param d the handler to call when an exit occurs at v
    ///
    void add_handler(vmcs_n::value_type v, handler_delegate_t &&d);

    /// Enable trapping
    ///
    /// @expects
    /// @ensures
    ///
    /// Enable external-interrupt exiting. This vcpu will exit each time
    /// an external-interrupt arrives during VMX-nonroot operation.
    ///
    void enable_exiting() const;

    /// Handle
    ///
    /// Invoke the handler listening for external-interrupt exits at the
    /// vector in the vmcs_n::vm_exit_interruption_information field
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs state passed to each handler
    ///
    bool handle(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);

    /// Dump Log
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log() final;

    /// @cond

    external_interrupt(external_interrupt &&) = default;
    external_interrupt &operator=(external_interrupt &&) = default;

    external_interrupt(const external_interrupt &) = delete;
    external_interrupt &operator=(const external_interrupt &) = delete;

    /// @endcond

private:

    exit_handler_t *m_exit_handler;
    std::array<std::list<handler_delegate_t>, 256> m_handlers{};

    struct record_t {
        uint64_t vector;
    };

    std::list<record_t> m_log;
};

}
}

#endif
