//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_EAPIS_H
#define VMCS_INTEL_X64_EAPIS_H

#include <gsl/gsl>

#include <vector>
#include <memory>

#include <vmcs/vmcs_intel_x64.h>

#include <intrinsics/x64.h>
#include <intrinsics/msrs_x64.h>
#include <intrinsics/portio_x64.h>

#ifdef ECR_DEBUG
    #define ecr_dbg bfdebug
#else
    #define ecr_dbg if (0) bfdebug
#endif

/// WARNING:
///
/// All of these APIs operate on the currently loaded VMCS, as well as on
/// private members. If the currently loaded VMCS is not "this" vmcs,
/// corruption is almost certain. We _do not_ check to make sure that this case
/// is not possible because it would cost far too much to check the currently
/// loaded VMCS on every operation. Thus, the user should take great care to
/// ensure that these APIs are used on the currently loaded VMCS. If this is
/// not the case, run vmcs->load() first to ensure the right VMCS is being
/// used.
///

class vmcs_intel_x64_eapis : public vmcs_intel_x64
{
public:

    using integer_pointer = uintptr_t;
    using port_type = x64::portio::port_addr_type;
    using msr_type = x64::msrs::field_type;
    using preemption_value_type = x64::msrs::value_type;

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vmcs_intel_x64_eapis();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcs_intel_x64_eapis() override  = default;

    /// Enable VPID
    ///
    /// Enables VPID. VPIDs cannot be reused. Re-Enabling VPID
    /// will not consume an additional VPID, but creating a new
    /// VMCS will, so reuse VMCS structures if possible.
    ///
    /// Example:
    /// @code
    /// this->enable_vpid();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_vpid();

    /// Disable VPID
    ///
    /// Disables VPID, and sets the VPID in the VMCS to 0.
    ///
    /// Example:
    /// @code
    /// this->disable_vpid();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_vpid();

    /// Enable IO Bitmaps
    ///
    /// Example:
    /// @code
    /// this->enable_io_bitmaps();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_io_bitmaps();

    /// Disable IO Bitmaps
    ///
    /// Example:
    /// @code
    /// this->disable_io_bitmaps();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_io_bitmaps();

    /// Trap On IO Access
    ///
    /// Sets a '1' in the IO bitmaps corresponding with the provided port. All
    /// attempts made by the guest to read/write from/to the provided port will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// // Trap on PCI configuration space reads / writes
    /// this->trap_on_io_access(0xCF8);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to trap on
    ///
    void trap_on_io_access(port_type port);

    /// Trap On All IO Access
    ///
    /// Sets a '1' in the IO bitmaps corresponding with all of the ports. All
    /// attempts made by the guest to read/write from/to any port will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// // Trap on all port IO access
    /// this->trap_on_all_io_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_io_accesses();

    /// Pass Through IO Access
    ///
    /// Sets a '0' in the IO bitmaps corresponding with the provided port. All
    /// attempts made by the guest to read/write from/to the provided port will
    /// be executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// // Pass through PCI configuration space reads / writes
    /// this->pass_through_io_access(0xCF8);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to pass through
    ///
    void pass_through_io_access(port_type port);

    /// Pass Through All IO Access
    ///
    /// Sets a '0' in the IO bitmaps corresponding with all of the ports. All
    /// attempts made by the guest to read/write from/to any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// // Pass through all port IO access
    /// this->pass_through_all_io_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_io_accesses();

    /// Enable EPT
    ///
    /// Enables EPT, and sets up the EPT Pointer (EPTP) in the VMCS.
    /// By default, the EPTP is setup with the paging structures to use
    /// write_back memory, and the accessed / dirty bits are disabled.
    /// Once enabling EPT, you can change these values if desired.
    ///
    /// Example:
    /// @code
    /// this->enable_ept();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_ept();

    /// Disable EPT
    ///
    /// Disables EPT, and sets the EPT Pointer (EPTP) in the VMCS to 0.
    ///
    /// Example:
    /// @code
    /// this->disable_ept();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_ept();

    /// Set EPTP
    ///
    /// Sets the EPTP field in the VMCS to point to the provided EPTP. Note
    /// that write back memory is used for the EPTs.
    ///
    /// Example:
    /// @code
    /// this->set_eptp(root_ept->eptp());
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param eptp the eptp value to use. This should come from the
    ///     root_ept_intel_x64->eptp() function.
    ///
    void set_eptp(integer_pointer eptp);

    /// Enable MSR Bitmap
    ///
    /// Example:
    /// @code
    /// this->enable_msr_bitmap();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_msr_bitmap();

    /// Disable MSR Bitmap
    ///
    /// Example:
    /// @code
    /// this->disable_msr_bitmap();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_msr_bitmap();

    /// Trap On Read MSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_rdmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    void trap_on_rdmsr_access(msr_type msr);

    /// Trap On Write MSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to write to the provided msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_wrmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    void trap_on_wrmsr_access(msr_type msr);

    /// Trap On All Read MSR Accesses
    ///
    /// Sets a '1' in the MSR bitmap corresponding with all of the msrs. All
    /// attempts made by the guest to read from any msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_rdmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_rdmsr_accesses();

    /// Trap On All Write MSR Accesses
    ///
    /// Sets a '1' in the MSR bitmap corresponding with all of the msrs. All
    /// attempts made by the guest to write to any msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_wrmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_wrmsr_accesses();

    /// Pass Through Read MSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_rdmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    void pass_through_rdmsr_access(msr_type msr);

    /// Pass Through Write MSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to write to the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_rdmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    void pass_through_wrmsr_access(msr_type msr);

    /// Pass Through All Read MSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with all of the ports. All
    /// attempts made by the guest to read from any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_rdmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_rdmsr_accesses();

    /// Pass Through All Write MSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with all of the ports. All
    /// attempts made by the guest to write to any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_wrmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_wrmsr_accesses();

protected:

    void write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                      gsl::not_null<vmcs_intel_x64_state *> guest_state) override;

protected:

    intel_x64::vmcs::value_type m_vpid;

    std::unique_ptr<uint8_t[]> m_io_bitmapa;
    std::unique_ptr<uint8_t[]> m_io_bitmapb;
    gsl::span<uint8_t> m_io_bitmapa_view;
    gsl::span<uint8_t> m_io_bitmapb_view;

    std::unique_ptr<uint8_t[]> m_msr_bitmap;
    gsl::span<uint8_t> m_msr_bitmap_view;

public:

    friend class eapis_ut;

    vmcs_intel_x64_eapis(vmcs_intel_x64_eapis &&) = default;
    vmcs_intel_x64_eapis &operator=(vmcs_intel_x64_eapis &&) = default;

    vmcs_intel_x64_eapis(const vmcs_intel_x64_eapis &) = delete;
    vmcs_intel_x64_eapis &operator=(const vmcs_intel_x64_eapis &) = delete;
};

#endif
