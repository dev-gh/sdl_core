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
    , active_call_back_()
    , rc_plugin_(rc_plugin) {}

AcquireResult::eType ResourceAllocationManagerImpl::AcquireResource(
    const std::string& module_type, const uint32_t app_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  const application_manager::ApplicationSharedPtr acquiring_app =
      rc_plugin_.service()->GetApplication(app_id);
  if (!acquiring_app) {
    LOG4CXX_WARN(logger_, "App with app_id: " << app_id << "does not exist!");
    return AcquireResult::IN_USE;
  }

  if (IsModuleTypeRejected(module_type, app_id)) {
    LOG4CXX_DEBUG(logger_,
                  "Driver disallowed app: " << app_id << " to acquire "
                                            << module_type);
    return AcquireResult::REJECTED;
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
    return AcquireResult::ALLOWED;
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

  DCHECK_OR_RETURN_VOID(allocated_resources_.end() != allocated_it)
  LOG4CXX_DEBUG(logger_, "Resource " << module_type << " is acquired.");
  LOG4CXX_DEBUG(logger_, "Owner application id is " << allocated_it->second);
  LOG4CXX_DEBUG(logger_, "Changing application id is " << app_id);
  DCHECK_OR_RETURN_VOID(app_id == allocated_it->second);

  resources_state_[module_type] = state;
  LOG4CXX_DEBUG(logger_, "Resource" << module_type << " got state " << state);
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
  current_access_mode_ = access_mode;
}

void ResourceAllocationManagerImpl::AskDriver(const std::string& module_type,
                                              const uint32_t hmi_app_id,
                                              AskDriverCallBackPtr callback) {
  LOG4CXX_AUTO_TRACE(logger_);
  DCHECK(callback);
  // Create GetInteriorConsent request to HMI
  Json::Value params;
  params[message_params::kModuleType] = module_type;
  application_manager::MessagePtr message_to_send =
      remote_control::MessageHelper::CreateHmiRequest(
          functional_modules::hmi_api::get_user_consent,
          hmi_app_id,
          params,
          rc_plugin_);

  LOG4CXX_DEBUG(logger_,
                "Request to HMI: \n" << message_to_send->json_message());
  // Send GetInteriorConsent request to HMI
  rc_plugin_.service()->SendMessageToHMI(message_to_send);

  // Execute callback on response
  rc_plugin_.event_dispatcher().add_observer(message_to_send->function_name(),
                                             message_to_send->correlation_id(),
                                             callback.get());
  active_call_back_ = callback;
}

ResourceAllocationManagerImpl::~ResourceAllocationManagerImpl() {}

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

ResourceAllocationManager::~ResourceAllocationManager() {}
}  // namespace remote_control
