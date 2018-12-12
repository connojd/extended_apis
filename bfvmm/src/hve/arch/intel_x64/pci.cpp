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

#include <arch/x64/portio.h>
#include <hve/arch/intel_x64/pci.h>
#include <hve/arch/intel_x64/vcpu.h>

// --------------------------------------------------------------------------
// Namespaces
// --------------------------------------------------------------------------

using namespace ::x64::portio;
using namespace ::intel_x64::pci::iocfg;
using namespace ::eapis::intel_x64;

// --------------------------------------------------------------------------
// Macros
// --------------------------------------------------------------------------

#define mk_hdlr(h) \
    io_instruction_handler::handler_delegate_t::create<pci_handler, &pci_handler::h>(this)

#define add_iocfg_hdlrs(p, in, out) \
        m_vcpu->add_io_instruction_handler(p, mk_hdlr(in), mk_hdlr(out))

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

namespace eapis::intel_x64 {

bool pci_config_in(
    ::intel_x64::pci::iocfg::addr_t cf8,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    using namespace ::x64::portio;
    namespace io = vmcs_n::exit_qualification::io_instruction;

    ::x64::portio::outd(0xCF8, cf8);
    auto port = info.port_number;

    switch (info.size_of_access) {
        case io::size_of_access::one_byte:  info.val = inb(port); break;
        case io::size_of_access::two_byte:  info.val = inw(port); break;
        case io::size_of_access::four_byte: info.val = ind(port); break;
        default: bfdebug_nhex(0,
            "invalid portio in size:", info.size_of_access);
            return false;
    }

    return true;
}

bool pci_config_out(
    ::intel_x64::pci::iocfg::addr_t cf8,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    using namespace ::x64::portio;
    namespace io = vmcs_n::exit_qualification::io_instruction;

    ::x64::portio::outd(0xCF8, cf8);
    auto port = info.port_number;

    switch (info.size_of_access) {
        case io::size_of_access::one_byte:  outb(port, info.val); break;
        case io::size_of_access::two_byte:  outw(port, info.val); break;
        case io::size_of_access::four_byte: outd(port, info.val); break;
        default: bfdebug_nhex(0,
            "invalid portio in size:", info.size_of_access);
            return false;
    }

    return true;
}
}

// --------------------------------------------------------------------------
// Implementation
// --------------------------------------------------------------------------

pci_handler::pci_handler(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    add_iocfg_hdlrs(0xCF8, handle_in_addr, handle_out_addr);

    add_iocfg_hdlrs(0xCFC, handle_in_data, handle_out_data);
    add_iocfg_hdlrs(0xCFD, handle_in_data, handle_out_data);
    add_iocfg_hdlrs(0xCFE, handle_in_data, handle_out_data);
    add_iocfg_hdlrs(0xCFF, handle_in_data, handle_out_data);

    // If emulation isn't handled correctly, it's possible that linux will
    // think it's running on hardware from the PCI 1.0 era and will try to use
    // the config access mechanism from that version.
    //
    // While not really a show-stopper, it usually means something has gone
    // wrong with the PCI emulation, so we alert the user if this is the case.
    //
    // See arch/x86/pci/direct.c in linux for more info
    //
    add_iocfg_hdlrs(0xCF9, handle_in_alert, handle_out_alert);
    add_iocfg_hdlrs(0xCFA, handle_in_alert, handle_out_alert);
    add_iocfg_hdlrs(0xCFB, handle_in_alert, handle_out_alert);
}

// --------------------------------------------------------------------------
// Handler registration
// --------------------------------------------------------------------------

void pci_handler::add_in_handler(const pci_handler::pred_t &p,
                                 const pci_handler::hdlr_t &h)
{ m_in_list.push_front(std::make_pair(std::move(p), std::move(h))); }

void pci_handler::add_out_handler(const pci_handler::pred_t &p,
                                  const pci_handler::hdlr_t &h)
{ m_out_list.push_front(std::make_pair(std::move(p), std::move(h))); }

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

bool pci_handler::handle_in_alert(gsl::not_null<vcpu_t *> vcpu,
                                  pci_handler::info_t &info)
{
    bfignored(vcpu);

    bfalert_info(0, "PCI: read from unexpected port");
    bfalert_subnhex(0, "port", info.port_number);
    bfalert_subnhex(0, "size", info.size_of_access + 1);

    return true;
}

bool pci_handler::handle_out_alert(gsl::not_null<vcpu_t *> vcpu,
                                   pci_handler::info_t &info)
{
    bfignored(vcpu);

    bfalert_info(0, "PCI: write to unexpected port");
    bfalert_subnhex(0, "port", info.port_number);
    bfalert_subnhex(0, "size", info.size_of_access + 1);
    bfalert_subnhex(0, "data", info.val);

    return true;
}

bool pci_handler::handle_in_addr(gsl::not_null<vcpu_t *> vcpu,
                                 pci_handler::info_t &info)
{
    info.val = m_cf8;
    return true;
}

bool pci_handler::handle_out_addr(gsl::not_null<vcpu_t *> vcpu,
                                  pci_handler::info_t &info)
{
    m_cf8 = info.val;
    return true;
}

bool pci_handler::handle_in_data(gsl::not_null<vcpu_t *> vcpu,
                                 pci_handler::info_t &info)
{
    for (const auto &pair : m_in_list) {
        const auto need_callback = pair.first;
        if (!need_callback(m_cf8, info)) {
            continue;
        }

        return pair.second(vcpu, info, m_cf8);
    }

    return false;
}

bool pci_handler::handle_out_data(gsl::not_null<vcpu_t *> vcpu,
                                  pci_handler::info_t &info)
{
    for (const auto &pair : m_out_list) {
        const auto need_callback = pair.first;
        if (!need_callback(m_cf8, info)) {
            continue;
        }

        return pair.second(vcpu, info, m_cf8);
    }

    return false;
}
