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

#include <bfvmm/vcpu/vcpu_factory.h>

#include <vcpu/arch/intel_x64/vcpu.h>
#include <vic/arch/intel_x64/isr.h>
#include <hve/arch/intel_x64/irq.h>
#include <hve/arch/intel_x64/irq_window.h>

//namespace eapis
//{
//namespace intel_x64
//{
//
//static const auto vector = 42;
//
//bool handle_irq(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
//{
//    return false;
//}
//
//bool handle_irq_window(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
//{
//    return false;
//}
//
//class vcpu : public bfvmm::intel_x64::vcpu
//{
//public:
//    vcpu(vcpuid::type id) :
//        bfvmm::intel_x64::vcpu{id}
//    {
//        using vmcs_t = bfvmm::intel_x64::vmcs;
//        using handler_t = delegate<bool(gsl::not_null<vmcs_t *>)>;
//
//        auto exit_hdlr = this->exit_handler();
//
//        isr::init_vmm_idt(exit_hdlr);
//
//        m_irq = std::make_unique<eapis::intel_x64::irq>(exit_hdlr);
//        m_irq->add_handler(vector, handler_t::create<handle_irq>());
//
//        m_irqwin = std::make_unique<eapis::intel_x64::irq_window>(exit_hdlr);
//        m_irqwin->add_handler(handler_t::create<handle_irq_window>());
//    }
//
//    ~vcpu() override
//    {
//    }
//
//private:
////    std::unique_ptr<eapis::intel_x64::rdmsr> m_rdmsr;
////    std::unique_ptr<eapis::intel_x64::wrmsr> m_wrmsr;
////    std::unique_ptr<eapis::intel_x64::cr_access> m_cr8;
//    std::unique_ptr<eapis::intel_x64::irq> m_irq;
//    std::unique_ptr<eapis::intel_x64::irq_window> m_irqwin;
//};
//
//} // namespace intel_x64
//} // namespace eapis

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<eapis::intel_x64::vcpu>(vcpuid);
}

}
