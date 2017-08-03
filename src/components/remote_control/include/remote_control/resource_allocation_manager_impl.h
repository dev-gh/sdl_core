#ifndef SRC_COMPONENTS_REMOTE_CONTROL_INCLUDE_REMOTE_CONTROL_RESOURCE_ALLOCATION_IMPL_H
#define SRC_COMPONENTS_REMOTE_CONTROL_INCLUDE_REMOTE_CONTROL_RESOURCE_ALLOCATION_IMPL_H
#include "remote_control/resource_allocation_manager.h"
#include "remote_control/remote_plugin_interface.h"
#include "utils/macro.h"
namespace remote_control {

typedef rc_event_engine::EventDispatcher<application_manager::MessagePtr,
                                         std::string> RCEventDispatcher;

class ResourceAllocationManagerImpl : public ResourceAllocationManager {
 public:
  ResourceAllocationManagerImpl(RemotePluginInterface& rc_plugin);

  AcquireResult::eType AcquireResource(const std::string& module_type,
                                       const uint32_t app_id) OVERRIDE FINAL;

  void SetResourceState(const std::string& module_type,
                        const uint32_t app_id,
                        const ResourceState::eType state) OVERRIDE FINAL;

  bool IsResourceFree(const std::string& module_type) const OVERRIDE FINAL;

  void AskDriver(const std::string& module_type,
                 const uint32_t hmi_app_id,
                 AskDriverCallBackPtr callback) OVERRIDE FINAL;

  void SetAccessMode(
      const hmi_apis::Common_RCAccessMode::eType access_mode) FINAL;
  ~ResourceAllocationManagerImpl();

  void ForceAcquireResource(const std::string& module_type,
                            const uint32_t app_id) OVERRIDE FINAL;

  void OnDriverDisallowed(const std::string& module_type,
                          const uint32_t app_id) OVERRIDE FINAL;

 private:
  bool IsModuleTypeRejected(const std::string& module_type,
                            const uint32_t app_id);

  /**
   * @brief AllocatedResources contains link between resource and application
   * owning that resource
   */
  typedef std::map<std::string, uint32_t> AllocatedResources;
  AllocatedResources allocated_resources_;

  /**
   * @brief ResourcesState contains states of ALLOCATED resources
   */
  typedef std::map<std::string, ResourceState::eType> ResourcesState;
  ResourcesState resources_state_;

  /**
   * @brief RejectedResources type for connecting list of resources rejected by
   * driver for application
   * application_id : [vector of rejected resources]
   */
  typedef std::map<uint32_t, std::vector<std::string> > RejectedResources;
  RejectedResources rejected_resources_for_application_;

  hmi_apis::Common_RCAccessMode::eType current_access_mode_;
  AskDriverCallBackPtr active_call_back_;
  RemotePluginInterface& rc_plugin_;
};
}  // remote_control

#endif  // SRC_COMPONENTS_REMOTE_CONTROL_INCLUDE_REMOTE_CONTROL_RESOURCE_ALLOCATION_IMPL_H
