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

#ifndef INTERRUPT_WINDOW_INTEL_X64_EAPIS_H
#define INTERRUPT_WINDOW_INTEL_X64_EAPIS_H

#include <deque>

#include "base.h"

namespace eapis
{
namespace intel_x64
{

///
/// Interrupt-window exit
///
class EXPORT_EAPIS_HVE interrupt_window final : public base
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    interrupt_window(gsl::not_null<exit_handler_t *> exit_handler);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~interrupt_window() = default;

    /// Add handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an interrupt-window exit occurs
    ///
    void add_handler(handler_delegate_t &&d);

    /// Queue interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// Queue an interrupt for injection at the given vector
    ///
    /// @param vector the vector at which to queue the interrupt
    ///
    void queue_interrupt(vmcs_n::value_type vector);

    /// Handle
    ///
    /// Invoke the handlers listening for interrupt-window exits
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs state passed to each handler
    ///
    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// Is open
    ///
    /// @expects
    /// @ensures
    ///
    /// @return true if and only if an external interrupt may be injected
    ///         on vm entry
    static bool is_open();

    /// @cond

    interrupt_window(interrupt_window &&) = default;
    interrupt_window &operator=(interrupt_window &&) = default;

    interrupt_window(const interrupt_window &) = delete;
    interrupt_window &operator=(const interrupt_window &) = delete;

    /// @endcond

private:

    void enable_trapping() const;
    void disable_trapping() const;
    void inject_interrupt(vmcs_n::value_type vector) const;

    exit_handler_t *m_exit_handler;
    std::list<handler_delegate_t> m_handlers{};
    std::deque<vmcs_n::value_type> m_irr{};
};

}
}

#endif
