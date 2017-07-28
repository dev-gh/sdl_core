#include "remote_control/resource_allocation_manager_impl.h"
#include "application_manager/application.h"

namespace remote_control {

CREATE_LOGGERPTR_GLOBAL(logger_, "RemoteControlModule")

ResourceAllocationManagerImpl::ResourceAllocationManagerImpl(
    RemotePluginInterface& rc_plugin)
    : current_access_mode_(AccessMode::AUTO_ALLOW)
    , active_call_back_()
    , rc_plugin_(rc_plugin) {}

AcquireResult::eType ResourceAllocationManagerImpl::AcquireResource(
    const std::string& module_type, uint32_t app_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  const application_manager::ApplicationSharedPtr acquiring_app =
      rc_plugin_.service()->GetApplication(app_id);
  if (!acquiring_app) {
    LOG4CXX_WARN(logger_, "App with app_id " << app_id << "does not exist!");
    return AcquireResult::IN_USE;
  }

  const AllocatedResources::const_iterator allocated_it =
      allocated_resources_.find(module_type);
  if (allocated_resources_.end() == allocated_it) {
    allocated_resources_[module_type] = app_id;
    LOG4CXX_DEBUG(logger_,
                  "Resource is not acquired yet. "
                  "Allow "
                      << app_id << " acquiring " << module_type);
    return AcquireResult::ALLOWED;
  }

  const mobile_apis::HMILevel::eType acquiring_app_hmi_level =
      acquiring_app->hmi_level();
  if (mobile_apis::HMILevel::HMI_FULL != acquiring_app_hmi_level) {
    LOG4CXX_DEBUG(logger_,
                  "Aquiring resources not alllowed in "
                      << acquiring_app_hmi_level << " hmi level. "
                      << "Disallow " << app_id << " acquiring " << module_type);
    return AcquireResult::IN_USE;
  }

  switch (current_access_mode_) {
    case AccessMode::AUTO_DENY: {
      LOG4CXX_DEBUG(logger_,
                    "Current access_mode is AUTO_DENY. "
                    "Disallow "
                        << app_id << " acquiring " << module_type);
      return AcquireResult::IN_USE;
    }
    case AccessMode::ASK_DRIVER: {
      LOG4CXX_DEBUG(logger_,
                    "Current access_mode is ASK_DRIVER. "
                    "Driver confirmation required to allow "
                        << app_id << " acquiring " << module_type);
      return AcquireResult::ASK_DRIVER;
    }
    case AccessMode::AUTO_ALLOW: {
      LOG4CXX_DEBUG(logger_,
                    "Current access_mode is AUTO_ALLOW. "
                    "Disallow "
                        << app_id << " acquiring " << module_type);
      allocated_resources_[module_type] = app_id;
      return AcquireResult::ALLOWED;
    }
    default: { DCHECK_OR_RETURN(false, AcquireResult::IN_USE); }
  }
}

void ResourceAllocationManagerImpl::SetAccessMode(
    AccessMode::eType access_mode) {
  current_access_mode_ = access_mode;
}

void ResourceAllocationManagerImpl::AskDriver(const std::string& module_type,
                                              uint32_t app_id,
                                              AskDriverCallBackPtr callback) {
  LOG4CXX_AUTO_TRACE(logger_);
  // Send GetInteriorConsent
  // subscribe on GetInteriorConsent response
  // execute callback on response
  // event_dispatcher_.add_observer(function_id, msg[kId].asInt(), callback);
  active_call_back_ = callback;
}

ResourceAllocationManagerImpl::~ResourceAllocationManagerImpl() {}

void ResourceAllocationManagerImpl::ForceAcquireResource(
    const std::string& module_type, uint32_t app_id) {
  LOG4CXX_DEBUG(logger_, "Force " << app_id << " acquiring " << module_type);
  allocated_resources_[module_type] = app_id;
}

void ResourceAllocationManagerImpl::OnDriverDisallowed(
    const std::string& module_type, uint32_t app_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  RejectedResources::iterator it =
      rejected_resources_for_application_.find(app_id);

  if (rejected_resources_for_application_.end() == it) {
    rejected_resources_for_application_[app_id] = std::vector<std::string>();
  }
  std::vector<std::string>& list_of_rejected_resources =
      rejected_resources_for_application_[app_id];
  list_of_rejected_resources.push_back(module_type);
}

ResourceAllocationManager::~ResourceAllocationManager() {}
}  // namespace remote_control
