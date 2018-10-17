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

#include <list>
#include <cstdint>
#include <algorithm>

#include <arch/x64/rdtsc.h>
#include <arch/intel_x64/msrs.h>

#include <bfvmm/vcpu/vcpu_factory.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <eapis/hve/arch/intel_x64/time.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

#ifndef SAMPLE_SIZE
#define SAMPLE_SIZE 256
#endif

class vcpu : public eapis::intel_x64::vcpu
{
    uint64_t m_start{0};
    uint64_t m_end{0};
    uint64_t m_count;

    std::list<uint64_t> m_sample;

public:
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        eapis()->add_vmx_preemption_timer_handler(
            vmx_preemption_timer_handler::handler_delegate_t::create<
            vcpu, &vcpu::handler>(this)
        );

        if (!eapis::intel_x64::time::invariant_tsc_supported()) {
            return;
        }

        eapis()->enable_vmx_preemption_timer();
        eapis()->set_vmx_preemption_timer(0);

        m_start = ::x64::read_tsc::get();
    }

    bool handler(gsl::not_null<vmcs_t *> vmcs)
    {
        bfignored(vmcs);

        m_end = ::x64::read_tsc::get();
        m_count++;

        if (m_count > SAMPLE_SIZE) {
            eapis()->disable_vmx_preemption_timer();
            return true;
        }

        m_sample.push_front(m_end - m_start);
        m_start = ::x64::read_tsc::get();

        return true;
    }

    ~vcpu()
    {
        uint64_t sum = std::accumulate(m_sample.begin(), m_sample.end(), 0);
        uint64_t tsc = sum >> 8; // Divide by SAMPLE_SIZE
        uint64_t ticks_per_usec = eapis::intel_x64::time::vpt_freq_MHz();
        uint64_t div = ::intel_x64::msrs::ia32_vmx_misc::preemption_timer_decrement::get();

        // NOTE: we should try to avoid / here. We could use multiplies and shifts
        // or we could start a static table of 'ticks_per_usec', and then at initialization
        // assign a conversion function that has compile-time constants so the compiler
        // will do the mult/shift for us.
        bfdebug_ndec(0, "Avg vmentry->vmexit latency (us)", tsc / ticks_per_usec);
        bfdebug_ndec(0, "Avg vmentry->vmexit latency TSC ticks", tsc);
        bfdebug_ndec(0, "Avg vmentry->vmexit latency VPT ticks", tsc >> div);
    }
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
