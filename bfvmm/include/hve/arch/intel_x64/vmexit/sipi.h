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

#ifndef SIPI_INTEL_X64_EAPIS_H
#define SIPI_INTEL_X64_EAPIS_H

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class vcpu;

/// SIPI handler
///
/// Provides an interface for registering handlers of SIPI exits
///
class EXPORT_EAPIS_HVE sipi_handler : public base
{
public:

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t = delegate<bool(gsl::not_null<vmcs_t *>)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this sipi handler
    ///
    sipi_handler(gsl::not_null<eapis::intel_x64::vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~sipi_handler() = default;

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(handler_delegate_t &&d);

    /// Dump Log
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log() final;

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    gsl::not_null<exit_handler_t *> m_exit_handler;
    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    sipi_handler(sipi_handler &&) = default;
    sipi_handler &operator=(sipi_handler &&) = default;

    sipi_handler(const sipi_handler &) = delete;
    sipi_handler &operator=(const sipi_handler &) = delete;

    /// @endcond
};

}
}

#endif
