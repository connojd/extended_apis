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

#ifndef EPT_VIOLATION_INTEL_X64_H
#define EPT_VIOLATION_INTEL_X64_H

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class vcpu;

/// EPT Violation
///
/// Provides an interface for registering handlers for EPT violation
/// exits.
///
class EXPORT_EAPIS_HVE ept_violation_handler : public base
{
public:

    ///
    /// Info
    ///
    /// This struct is created by ept_violation_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// GVA (in)
        ///
        /// The guest virtual (linear) address that caused the exit
        ///
        uint64_t gva;

        /// GPA (in)
        ///
        /// The guest physical address that caused the exit
        ///
        uint64_t gpa;

        /// Exit qualification (in)
        ///
        /// The VMCS exit qualification that caused the exit
        ///
        uint64_t exit_qualification;

        /// Ignore advance (out)
        ///
        /// If true, do not advance the guest's instruction pointer.
        /// Set this to true if your handler returns true and has already
        /// advanced the guest's instruction pointer.
        ///
        /// default: false
        ///
        bool ignore_advance;
    };

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this EPT violation handler
    ///
    ept_violation_handler(gsl::not_null<eapis::intel_x64::vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_violation_handler() final;

public:

    /// Add Read EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_read_handler(handler_delegate_t &&d);

    /// Add Write EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_write_handler(handler_delegate_t &&d);

    /// Add Execute EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_execute_handler(handler_delegate_t &&d);

    /// Dump Log
    ///
    /// Example:
    /// @code
    /// this->dump_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log() final;

private:

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    bool handle_read(gsl::not_null<vmcs_t *> vmcs, info_t &info);
    bool handle_write(gsl::not_null<vmcs_t *> vmcs, info_t &info);
    bool handle_execute(gsl::not_null<vmcs_t *> vmcs, info_t &info);

    /// @endcond

private:

    gsl::not_null<exit_handler_t *> m_exit_handler;

    std::list<handler_delegate_t> m_read_handlers;
    std::list<handler_delegate_t> m_write_handlers;
    std::list<handler_delegate_t> m_execute_handlers;

private:

    struct record_t {
        uint64_t gva;
        uint64_t gpa;
        uint64_t exit_qualification;
    };

    std::list<record_t> m_log;

public:

    /// @cond

    ept_violation_handler(ept_violation_handler &&) = default;
    ept_violation_handler &operator=(ept_violation_handler &&) = default;

    ept_violation_handler(const ept_violation_handler &) = delete;
    ept_violation_handler &operator=(const ept_violation_handler &) = delete;

    /// @endcond
};

}
}

#endif
