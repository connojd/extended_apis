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

#ifndef EFI_INTEL_X64_EAPIS_H
#define EFI_INTEL_X64_EAPIS_H

#include "../base.h"
#include "wrmsr.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class vcpu;

/// CPUID
///
/// Provides an interface for registering handlers for cpuid exits
/// at a given (leaf, subleaf).
///
class EXPORT_EAPIS_HVE efi_handler : public base
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this efi_handler
    ///
    efi_handler() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~efi_handler() = default;

    void add_handlers(gsl::not_null<apis *> apis);
    void dump_log() override {}

    // register with base
    bool handle_cpuid(gsl::not_null<vmcs_t *> vmcs);
    bool handle_rdmsr(gsl::not_null<vmcs_t *> vmcs);
    bool handle_init_signal(gsl::not_null<vmcs_t *> vmcs);
    bool handle_sipi(gsl::not_null<vmcs_t *> vmcs);

    bool handle_wrmsr_efer(gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info);
    bool handle_wrmsr_perf_global_ctrl(gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info);
    bool handle_icr_write(gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info);
    bool handle_wrcr0(gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info);
    bool handle_wrcr4(gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info);

public:

    uint64_t m_ia32_efer_shadow{};

    /// @cond

    efi_handler(efi_handler &&) = default;
    efi_handler &operator=(efi_handler &&) = default;

    efi_handler(const efi_handler &) = delete;
    efi_handler &operator=(const efi_handler &) = delete;

    /// @endcond
};

}
}

#endif
