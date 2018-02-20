// //
// // Bareflank Extended APIs
// // Copyright (C) 2018 Assured Information Security, Inc.
// //
// // This library is free software; you can redistribute it and/or
// // modify it under the terms of the GNU Lesser General Public
// // License as published by the Free Software Foundation; either
// // version 2.1 of the License, or (at your option) any later version.
// //
// // This library is distributed in the hope that it will be useful,
// // but WITHOUT ANY WARRANTY; without even the implied warranty of
// // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// // Lesser General Public License for more details.
// //
// // You should have received a copy of the GNU Lesser General Public
// // License along with this library; if not, write to the Free Software
// // Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

// #ifndef CRS_INTEL_X64_EAPIS_H
// #define CRS_INTEL_X64_EAPIS_H

// #include <bfgsl.h>

// #include <list>
// #include <unordered_map>

// #include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>
// #include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>

// // -----------------------------------------------------------------------------
// // Exports
// // -----------------------------------------------------------------------------

// #include <bfexports.h>

// #ifndef STATIC_EAPIS_HVE
// #ifdef SHARED_EAPIS_HVE
// #define EXPORT_EAPIS_HVE EXPORT_SYM
// #else
// #define EXPORT_EAPIS_HVE IMPORT_SYM
// #endif
// #else
// #define EXPORT_EAPIS_HVE
// #endif

// #ifdef _MSC_VER
// #pragma warning(push)
// #pragma warning(disable : 4251)
// #endif

// namespace eapis
// {
// namespace intel_x64
// {

// // -----------------------------------------------------------------------------
// // Definitions
// // -----------------------------------------------------------------------------

// /// MSR Handler
// ///
// ///
// class EXPORT_EAPIS_HVE msrs
// {
// public:

//     using msr_t = ::intel_x64::vmcs::value_type;

//     /// Constructor
//     ///
//     /// @expects
//     /// @ensures
//     ///
//     msrs(
//         gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler
//     );

//     /// Destructor
//     ///
//     /// @expects
//     /// @ensures
//     ///
//     ~msrs() = default;

// public:

//     /// @cond

//     msrs(msrs &&) = default;
//     msrs &operator=(msrs &&) = default;

//     msrs(const msrs &) = delete;
//     msrs &operator=(const msrs &) = delete;

//     /// @endcond
// };

// }
// }

// #ifdef _MSC_VER
// #pragma warning(pop)
// #endif

// #endif
