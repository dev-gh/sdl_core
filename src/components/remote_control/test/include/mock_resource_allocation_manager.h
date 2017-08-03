#ifndef SRC_COMPONENTS_REMOTE_CONTROL_TEST_INCLUDE_MOCK_RESOURCE_ALLOCATION_MANAGER_H_
#define SRC_COMPONENTS_REMOTE_CONTROL_TEST_INCLUDE_MOCK_RESOURCE_ALLOCATION_MANAGER_H_

#include "gmock/gmock.h"
#include "remote_control/resource_allocation_manager.h"

namespace test {
namespace components {
namespace remote_control_test {

class MockAskDriverCallBack : public remote_control::AskDriverCallBack {
 public:
  MOCK_METHOD1(
      on_event,
      void(const rc_event_engine::Event<application_manager::MessagePtr,
                                        std::string>& event));
};

class MockResourceAllocationManager
    : public remote_control::ResourceAllocationManager {
 public:
  MOCK_METHOD2(AcquireResource,
               remote_control::AcquireResult::eType(
                   const std::string& module_type, const uint32_t app_id));
  MOCK_METHOD2(ForceAcquireResource,
               void(const std::string& module_type, const uint32_t app_id));
  MOCK_METHOD2(OnDriverDisallowed,
               void(const std::string& module_type, const uint32_t app_id));
  MOCK_METHOD3(AskDriver,
               void(const std::string& module_type,
                    const uint32_t app_id,
                    remote_control::AskDriverCallBackPtr callback));
  MOCK_METHOD1(SetAccessMode,
               void(const hmi_apis::Common_RCAccessMode::eType access_mode));
  MOCK_METHOD3(SetResourceState,
               void(const std::string& module_type,
                    const uint32_t app_id,
                    const remote_control::ResourceState::eType state));
  MOCK_CONST_METHOD1(IsResourceFree, bool(const std::string& module_type));
};

}  // namespace remote_control_test
}  // namespace components
}  // namespace test

#endif  // SRC_COMPONENTS_REMOTE_CONTROL_TEST_INCLUDE_MOCK_RESOURCE_ALLOCATION_MANAGER_H_
