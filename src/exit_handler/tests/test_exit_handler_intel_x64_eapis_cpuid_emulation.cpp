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

#include <test_support.h>
#include <catch/catch.hpp>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("exit_handler_intel_x64_eapis_cpuid_emulation: passthrough not logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::cpuid);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_intel_x64_eapis::cpuid_type leaf = 0;
    exit_handler_intel_x64_eapis::cpuid_type subleaf = 0;
    exit_handler_intel_x64_eapis::cpuid_regs_type m_regs = x64::cpuid::get(leaf, 0, subleaf, 0);

    CHECK_NOTHROW(ehlr->log_cpuid_access(false));
    CHECK_NOTHROW(ehlr->clear_cpuid_access_log());
    ehlr->m_state_save->rax = leaf;
    ehlr->m_state_save->rcx = subleaf;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK_FALSE(ehlr->m_cpuid_access_log[0] == 1);
    CHECK(ehlr->m_cpuid_emu_map.empty());

    CHECK(ehlr->m_state_save->rax == m_regs.rax);
    CHECK(ehlr->m_state_save->rbx == m_regs.rbx);
    CHECK(ehlr->m_state_save->rcx == m_regs.rcx);
    CHECK(ehlr->m_state_save->rdx == m_regs.rdx);
}

TEST_CASE("exit_handler_intel_x64_eapis_cpuid_emulation: passthrough logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::cpuid);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_intel_x64_eapis::cpuid_type leaf = 0;
    exit_handler_intel_x64_eapis::cpuid_type subleaf = 0;
    exit_handler_intel_x64_eapis::cpuid_regs_type m_regs = x64::cpuid::get(leaf, 0, subleaf, 0);

    CHECK_NOTHROW(ehlr->log_cpuid_access(true));
    CHECK_NOTHROW(ehlr->clear_cpuid_access_log());
    ehlr->m_state_save->rax = leaf;
    ehlr->m_state_save->rcx = subleaf;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(ehlr->m_cpuid_access_log[0] == 1);
    CHECK(ehlr->m_cpuid_emu_map.empty());

    CHECK(ehlr->m_state_save->rax == m_regs.rax);
    CHECK(ehlr->m_state_save->rbx == m_regs.rbx);
    CHECK(ehlr->m_state_save->rcx == m_regs.rcx);
    CHECK(ehlr->m_state_save->rdx == m_regs.rdx);
}

TEST_CASE("exit_handler_intel_x64_eapis_cpuid_emulation: emulation not logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::cpuid);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_intel_x64_eapis::cpuid_type leaf = 0;
    exit_handler_intel_x64_eapis::cpuid_type subleaf = 0;
    exit_handler_intel_x64_eapis::cpuid_regs_type regs = { 1, 7, 3, 8 };
    ehlr->m_cpuid_emu_map[0] = regs;

    CHECK_NOTHROW(ehlr->log_cpuid_access(false));
    CHECK_NOTHROW(ehlr->clear_cpuid_access_log());
    ehlr->m_state_save->rax = leaf;
    ehlr->m_state_save->rcx = subleaf;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK_FALSE(ehlr->m_cpuid_access_log[0] == 1);
    CHECK_FALSE(ehlr->m_cpuid_emu_map.empty());

    CHECK(ehlr->m_state_save->rax == 1);
    CHECK(ehlr->m_state_save->rbx == 7);
    CHECK(ehlr->m_state_save->rcx == 3);
    CHECK(ehlr->m_state_save->rdx == 8);
}

TEST_CASE("exit_handler_intel_x64_eapis_cpuid_emulation: emulation logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::cpuid);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_intel_x64_eapis::cpuid_type leaf = 0;
    exit_handler_intel_x64_eapis::cpuid_type subleaf = 0;
    exit_handler_intel_x64_eapis::cpuid_regs_type regs = { 1, 7, 3, 8 };
    ehlr->m_cpuid_emu_map[0] = regs;

    CHECK_NOTHROW(ehlr->log_cpuid_access(true));
    CHECK_NOTHROW(ehlr->clear_cpuid_access_log());
    ehlr->m_state_save->rax = leaf;
    ehlr->m_state_save->rcx = subleaf;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(ehlr->m_cpuid_access_log[0] == 1);
    CHECK_FALSE(ehlr->m_cpuid_emu_map.empty());

    CHECK(ehlr->m_state_save->rax == 1);
    CHECK(ehlr->m_state_save->rbx == 7);
    CHECK(ehlr->m_state_save->rcx == 3);
    CHECK(ehlr->m_state_save->rdx == 8);
}

#endif