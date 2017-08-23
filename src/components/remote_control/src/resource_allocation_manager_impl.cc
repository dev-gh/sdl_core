#include "remote_control/resource_allocation_manager_impl.h"
#include "application_manager/application.h"
#include "application_manager/message_helper.h"
#include "remote_control/rc_module_constants.h"
#include "json/json.h"
#include "utils/helpers.h"
#include "utils/make_shared.h"
#include "remote_control/message_helper.h"

namespace remote_control {

CREATE_LOGGERPTR_GLOBAL(logger_, "RemoteControlModule")

ResourceAllocationManagerImpl::ResourceAllocationManagerImpl(
    RemotePluginInterface& rc_plugin)
    : current_access_mode_(hmi_apis::Common_RCAccessMode::AUTO_ALLOW)
    , rc_plugin_(rc_plugin) {}

ResourceAllocationManagerImpl::~ResourceAllocationManagerImpl() {}

AcquireResult::eType ResourceAllocationManagerImpl::AcquireResource(
    const std::string& module_type, const uint32_t app_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  const application_manager::ApplicationSharedPtr acquiring_app =
      rc_plugin_.service()->GetApplication(app_id);
  if (!acquiring_app) {
    LOG4CXX_WARN(logger_, "App with app_id: " << app_id << "does not exist!");
    return AcquireResult::IN_USE;
  }

  const AllocatedResources::const_iterator allocated_it =
      allocated_resources_.find(module_type);
  if (allocated_resources_.end() == allocated_it) {
    allocated_resources_[module_type] = app_id;
    LOG4CXX_DEBUG(logger_,
                  "Resource is not acquired yet. "
                      << "App: " << app_id << " is allowed to acquire "
                      << module_type);
    return AcquireResult::ALLOWED;
  }

  if (app_id == allocated_resources_[module_type]) {
    LOG4CXX_DEBUG(logger_,
                  "App: " << app_id << " is already acquired resource "
                          << module_type);
    return AcquireResult::ALLOWED;
  }

  if (IsModuleTypeRejected(module_type, app_id)) {
    LOG4CXX_DEBUG(logger_,
                  "Driver disallowed app: " << app_id << " to acquire "
                                            << module_type);
    return AcquireResult::REJECTED;
  }

  const mobile_apis::HMILevel::eType acquiring_app_hmi_level =
      acquiring_app->hmi_level();

  if (mobile_apis::HMILevel::HMI_FULL != acquiring_app_hmi_level) {
    LOG4CXX_DEBUG(
        logger_,
        "Aquiring resources is not allowed in HMI level: "
            << application_manager::MessageHelper::StringifiedHMILevel(
                   acquiring_app_hmi_level) << ". App: " << app_id
            << " is disallowed to acquire " << module_type);
    return AcquireResult::REJECTED;
  }

  switch (current_access_mode_) {
    case hmi_apis::Common_RCAccessMode::AUTO_DENY: {
      LOG4CXX_DEBUG(logger_,
                    "Current access_mode is AUTO_DENY. "
                        << "App: " << app_id << " is disallowed to acquire "
                        << module_type);
      return AcquireResult::IN_USE;
    }
    case hmi_apis::Common_RCAccessMode::ASK_DRIVER: {
      LOG4CXX_DEBUG(logger_,
                    "Current access_mode is ASK_DRIVER. "
                    "Driver confirmation is required for app: "
                        << app_id << " to acquire " << module_type);
      return AcquireResult::ASK_DRIVER;
    }
    case hmi_apis::Common_RCAccessMode::AUTO_ALLOW: {
      LOG4CXX_DEBUG(logger_,
                    "Current access_mode is AUTO_ALLOW. "
                        << "App: " << app_id << " is allowed to acquire "
                        << module_type);

      allocated_resources_[module_type] = app_id;
      return AcquireResult::ALLOWED;
    }
    default: { DCHECK_OR_RETURN(false, AcquireResult::IN_USE); }
  }
}

bool ResourceAllocationManagerImpl::ReleaseResource(
    const std::string& module_type, const uint32_t application_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  LOG4CXX_DEBUG(logger_, "Release " << module_type << " by " << application_id);
  AllocatedResources::const_iterator allocation =
      allocated_resources_.find(module_type);
  if (allocated_resources_.end() == allocation) {
    LOG4CXX_DEBUG(logger_, "Resource " << module_type << " is not allocated.");
    return false;
  }

  if (application_id != allocation->second) {
    LOG4CXX_DEBUG(logger_,
                  "Resource " << module_type
                              << " is allocated by different application "
                              << allocation->second);
    return false;
  }

  allocated_resources_.erase(allocation);
  LOG4CXX_DEBUG(logger_, "Resource " << module_type << " is released.");
  return true;
}

std::vector<std::string> ResourceAllocationManagerImpl::GetAcquiredResources(
    const uint32_t application_id) const {
  LOG4CXX_AUTO_TRACE(logger_);
  Resources allocated_resources;
  AllocatedResources::const_iterator allocation = allocated_resources_.begin();
  for (; allocated_resources_.end() != allocation; ++allocation) {
    if (application_id == allocation->second) {
      allocated_resources.push_back(allocation->first);
    }
  }

  LOG4CXX_DEBUG(logger_,
                "Application " << application_id << " acquired "
                               << allocated_resources.size());

  return allocated_resources;
}

void ResourceAllocationManagerImpl::SetResourceState(
    const std::string& module_type,
    const uint32_t app_id,
    const ResourceState::eType state) {
  LOG4CXX_AUTO_TRACE(logger_);
  LOG4CXX_DEBUG(logger_,
                "Setting state for " << module_type << " by app_id " << app_id
                                     << " to state " << state);
  const AllocatedResources::const_iterator allocated_it =
      allocated_resources_.find(module_type);

  const std::string status = allocated_resources_.end() != allocated_it
                                 ? " acquired "
                                 : " not acquired ";
  UNUSED(status);
  LOG4CXX_DEBUG(logger_,
                "Resource " << module_type << " is " << status
                            << " Owner application id is "
                            << allocated_it->second
                            << " Changing application id is " << app_id);

  resources_state_[module_type] = state;
  LOG4CXX_DEBUG(logger_, "Resource " << module_type << " got state " << state);
}

bool ResourceAllocationManagerImpl::IsResourceFree(
    const std::string& module_type) const {
  LOG4CXX_AUTO_TRACE(logger_);
  const ResourcesState::const_iterator resource =
      resources_state_.find(module_type);

  if (resources_state_.end() == resource) {
    LOG4CXX_DEBUG(logger_, "Resource " << module_type << " is free.");
    return true;
  }

  LOG4CXX_DEBUG(logger_,
                "Resource " << module_type << " state is " << resource->second);

  return ResourceState::FREE == resource->second;
}

void ResourceAllocationManagerImpl::SetAccessMode(
    const hmi_apis::Common_RCAccessMode::eType access_mode) {
  if (hmi_apis::Common_RCAccessMode::ASK_DRIVER != access_mode) {
    rejected_resources_for_application_.clear();
  }
  current_access_mode_ = access_mode;
}

hmi_apis::Common_RCAccessMode::eType
ResourceAllocationManagerImpl::GetAccessMode() const {
  return current_access_mode_;
}

void ResourceAllocationManagerImpl::ForceAcquireResource(
    const std::string& module_type, const uint32_t app_id) {
  LOG4CXX_DEBUG(logger_, "Force " << app_id << " acquiring " << module_type);
  allocated_resources_[module_type] = app_id;
}

bool ResourceAllocationManagerImpl::IsModuleTypeRejected(
    const std::string& module_type, const uint32_t app_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  RejectedResources::iterator it =
      rejected_resources_for_application_.find(app_id);

  if (rejected_resources_for_application_.end() == it) {
    return false;
  }

  const std::vector<std::string>& list_of_rejected_resources =
      rejected_resources_for_application_[app_id];

  return helpers::in_range(list_of_rejected_resources, module_type);
}

void ResourceAllocationManagerImpl::OnDriverDisallowed(
    const std::string& module_type, const uint32_t app_id) {
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

void ResourceAllocationManagerImpl::ResetAllAllocations() {
  LOG4CXX_AUTO_TRACE(logger_);
  allocated_resources_.clear();
  rejected_resources_for_application_.clear();
  resources_state_.clear();
}

}  // namespace remote_control
