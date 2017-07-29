#ifndef SRC_COMPONENTS_REMOTE_CONTROL_INCLUDE_REMOTE_CONTROL_RESOURCE_ALLOCATION_IMPL_H
#define SRC_COMPONENTS_REMOTE_CONTROL_INCLUDE_REMOTE_CONTROL_RESOURCE_ALLOCATION_IMPL_H
#include "remote_control/resource_allocation_manager.h"
#include "remote_control/remote_plugin_interface.h"
#include "utils/macro.h"
namespace remote_control {

/**
 * enum contains list of access modes
 */
namespace AccessMode {
enum eType { AUTO_ALLOW = 0, AUTO_DENY, ASK_DRIVER };
}  // AccessMode

typedef rc_event_engine::EventDispatcher<application_manager::MessagePtr,
                                         std::string> RCEventDispatcher;

class ResourceAllocationManagerImpl : public ResourceAllocationManager {
 public:
  ResourceAllocationManagerImpl(RemotePluginInterface& rc_plugin);

  AcquireResult::eType AcquireResource(const std::string& module_type,
                                       uint32_t app_id) OVERRIDE FINAL;
  void AskDriver(const std::string& module_type,
                 uint32_t app_id,
                 AskDriverCallBackPtr callback) OVERRIDE FINAL;

  void SetAccessMode(AccessMode::eType access_mode);
  ~ResourceAllocationManagerImpl();

  void ForceAcquireResource(const std::string& module_type,
                            uint32_t app_id) OVERRIDE FINAL;

  void OnDriverDisallowed(const std::string& module_type,
                          uint32_t app_id) OVERRIDE FINAL;

 private:
  typedef std::map<std::string, uint32_t> AllocatedResources;
  std::map<std::string, uint32_t> allocated_resources_;

  /**
   * @brief RejectedResources type for connecting list of resources rejected by
   * driver for application
   * application_id : [vector of rejected resources]
   */
  typedef std::map<uint32_t, std::vector<std::string> > RejectedResources;
  RejectedResources rejected_resources_for_application_;

  AccessMode::eType current_access_mode_;
  AskDriverCallBackPtr active_call_back_;
  RemotePluginInterface& rc_plugin_;
};
}  // remote_control

#endif  // SRC_COMPONENTS_REMOTE_CONTROL_INCLUDE_REMOTE_CONTROL_RESOURCE_ALLOCATION_IMPL_H
