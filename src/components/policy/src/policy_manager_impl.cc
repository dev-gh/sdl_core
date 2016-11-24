/*
 Copyright (c) 2013, Ford Motor Company
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following
 disclaimer in the documentation and/or other materials provided with the
 distribution.

 Neither the name of the Ford Motor Company nor the names of its contributors
 may be used to endorse or promote products derived from this software
 without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
 */
#include "policy/policy_manager_impl.h"

#include <algorithm>
#include <cmath>
#include <ctime>
#include <functional>
#include <iterator>
#include <limits>
#include <vector>
#include <queue>
#include <set>

#include "config_profile/profile.h"
#include "json/features.h"
#include "json/reader.h"
#include "json/writer.h"
#include "policy/policy_helper.h"
#include "policy/policy_table/enums.h"
#include "policy/policy_table.h"
#include "policy/pt_representation.h"
#include "policy/sql_pt_ext_representation.h"
#include "policy/update_status_manager.h"
#include "rpc_base/rpc_base.h"
#include "utils/date_time.h"
#include "utils/file_system.h"
#include "utils/gen_hash.h"
#include "utils/logger.h"
#include "utils/threads/thread_delegate.h"
#include "utils/threads/thread.h"
#include "utils/make_shared.h"

namespace policy_table = rpc::policy_table_interface_base;

namespace {

/**
 * @brief Looks for CCS entity in the list of entities
 * @param entities CCS entities list
 * @param entity Entity to look for
 * @return True if found in the list, otherwise - false
 */
bool IsEntityExists(const policy_table::DisallowedByCCSEntities& entities,
                    const policy_table::CCS_Entity& entity) {
  const policy_table::DisallowedByCCSEntities::const_iterator it_entity =
      std::find(entities.begin(), entities.end(), entity);

  return entities.end() != it_entity;
}

/**
 * @brief Looks for CCS entity in disallowed_by_ccs_entities_on/off sections
 * of each functional group
 */
struct GroupByEntityFinder
    : public std::unary_function<
          void,
          const policy_table::FunctionalGroupings::value_type&> {
  GroupByEntityFinder(const policy::CCSStatusItem& ccs_item,
                      policy::GroupsByCCSStatus& out_groups_by_ccs)
      : ccs_item_(ccs_item), out_groups_by_ccs_(out_groups_by_ccs) {}

  void operator()(
      const policy_table::FunctionalGroupings::value_type& group) const {
    if (!group.second.user_consent_prompt.is_initialized()) {
      return;
    }

    policy_table::CCS_Entity entity(ccs_item_.entity_type_,
                                    ccs_item_.entity_id_);
    const std::string group_name = group.first;

    if (IsEntityExists(*group.second.disallowed_by_ccs_entities_on, entity)) {
      const bool disallowed_by_ccs_entities_on_marker = true;
      out_groups_by_ccs_[ccs_item_].push_back(
          std::make_pair(group_name, disallowed_by_ccs_entities_on_marker));
    }

    if (IsEntityExists(*group.second.disallowed_by_ccs_entities_off, entity)) {
      const bool disallowed_by_ccs_entities_off_marker = false;
      out_groups_by_ccs_[ccs_item_].push_back(
          std::make_pair(group_name, disallowed_by_ccs_entities_off_marker));
    }
  }

 private:
  const policy::CCSStatusItem& ccs_item_;
  policy::GroupsByCCSStatus& out_groups_by_ccs_;
};

/**
 * @brief Maps CCS status item to the list of functional groups names specifying
 * container where item is found. If item is not found it won't be added.
 */
struct GroupByCCSItemFinder
    : public std::unary_function<void, const policy::CCSStatus::value_type&> {
  GroupByCCSItemFinder(const policy_table::FunctionalGroupings& groups,
                       policy::GroupsByCCSStatus& out_groups_by_ccs)
      : groups_(groups), out_groups_by_css_(out_groups_by_ccs) {}

  void operator()(const policy::CCSStatus::value_type& ccs_item) const {
    GroupByEntityFinder group_finder(ccs_item, out_groups_by_css_);
    std::for_each(groups_.begin(), groups_.end(), group_finder);
  }

 private:
  const policy_table::FunctionalGroupings& groups_;
  policy::GroupsByCCSStatus& out_groups_by_css_;
};

/**
 * @brief Template for getting 'first' of std::pair to use with standard
 * algorithm below
 */
template <typename T1, typename T2>
const T1& pair_first(const std::pair<T1, T2>& item) {
  return item.first;
}

/**
 * @brief Collects known links device-to-application form
 * device_data/user_consent_records is any record is present
 */
struct LinkCollector
    : public std::unary_function<void,
                                 const policy_table::DeviceData::value_type&> {
  typedef std::vector<policy_table::UserConsentRecords::key_type>
      ApplicationsIds;

  LinkCollector(policy::ApplicationsLinks& links) : links_(links) {}

  void operator()(const policy_table::DeviceData::value_type& value) {
    using namespace policy_table;

    device_id_ = value.first;

    ApplicationsIds applications_ids;
    std::transform(value.second.user_consent_records->begin(),
                   value.second.user_consent_records->end(),
                   std::back_inserter(applications_ids),
                   &pair_first<UserConsentRecords::key_type,
                               UserConsentRecords::mapped_type>);

    std::for_each(applications_ids.begin(),
                  applications_ids.end(),
                  std::bind1st(std::mem_fun(&LinkCollector::FillLinks), this));
  }

 private:
  void FillLinks(const ApplicationsIds::value_type app_id) const {
    links_.insert(std::make_pair(device_id_, app_id));
  }

  std::string device_id_;
  policy::ApplicationsLinks& links_;
};

/**
 * @brief Returns group consent record constructed from input group permissions
 */
struct CCSConsentGroupAppender
    : public std::unary_function<policy_table::ConsentGroups,
                                 const policy::FunctionalGroupPermission&> {
  policy_table::ConsentGroups::value_type operator()(
      const policy::FunctionalGroupPermission& value) const {
    return std::make_pair(value.group_name,
                          rpc::Boolean(value.state == policy::kGroupAllowed));
  }
};

/**
 * @brief Extracts group name from group permission structure
 */
struct GroupNamesAppender
    : public std::unary_function<void,
                                 const policy::FunctionalGroupPermission&> {
  GroupNamesAppender(policy_table::Strings& names) : names_(names) {}

  void operator()(const policy::FunctionalGroupPermission& value) {
    names_.push_back(value.group_name);
  }

 private:
  policy_table::Strings& names_;
};

/**
 * @brief Updates permission state of input group permission value in case
 * group name is found within allowed or disallowed groups lists
 * Also collects matched groups names to separate collection for futher
 * processing
 */
struct ConsentsUpdater
    : public std::unary_function<void, policy::FunctionalGroupPermission&> {
  ConsentsUpdater(
      const policy::GroupsNames& allowed,
      const policy::GroupsNames& disallowed,
      std::vector<policy::FunctionalGroupPermission>& out_ccs_matches)
      : allowed_(allowed)
      , disallowed_(disallowed)
      , out_ccs_matches_(out_ccs_matches) {}

  void operator()(policy::FunctionalGroupPermission& value) {
    using namespace policy;

    GroupsNames::iterator it_disallowed =
        std::find(disallowed_.begin(), disallowed_.end(), value.group_name);

    if (disallowed_.end() != it_disallowed) {
      value.state = kGroupDisallowed;
      out_ccs_matches_.push_back(value);
      return;
    }

    GroupsNames::iterator it_allowed =
        std::find(allowed_.begin(), allowed_.end(), value.group_name);

    if (allowed_.end() != it_allowed) {
      value.state = kGroupAllowed;
      out_ccs_matches_.push_back(value);
    }
  }

 private:
  const policy::GroupsNames& allowed_;
  const policy::GroupsNames& disallowed_;
  std::vector<policy::FunctionalGroupPermission>& out_ccs_matches_;
};

/**
 * @brief Checks whether CCS entity status is the same as name of group
 * container where entity has been found in. In case of match group is added to
 * 'disallowed' list, otherwise - to 'allowed' one.
 * E.g. if entity has "ON" status and is found in
 * 'disallowed_by_ccs_entities_on' it will be added to 'disallowed'. If it has
 * been found in 'disallowed_by_ccs_entities_off' than group is added to
 * 'allowed' list.
 */
struct GroupChecker
    : std::unary_function<void,
                          policy::GroupsByCCSStatus::mapped_type::value_type> {
  GroupChecker(const policy::EntityStatus entity_status,
               policy::GroupsNames& out_allowed,
               policy::GroupsNames& out_disallowed)
      : entity_status_(entity_status)
      , out_allowed_(out_allowed)
      , out_disallowed_(out_disallowed) {}

  void operator()(
      const policy::GroupsByCCSStatus::mapped_type::value_type value) {
    using namespace policy;

    const std::string group_name = value.first;

    if ((value.second && (kStatusOn == entity_status_)) ||
        (!value.second && (kStatusOff == entity_status_))) {
      out_disallowed_.insert(group_name);
    } else {
      out_allowed_.insert(group_name);
    }
  }

 private:
  const policy::EntityStatus entity_status_;
  policy::GroupsNames& out_allowed_;
  policy::GroupsNames& out_disallowed_;
};

/**
 * @brief Sorts groups for 'allowed' and 'disallowed' by CCS entities statuses.
 * Wraps GroupChecker logic.
 */
struct GroupSorter
    : std::unary_function<void, const policy::GroupsByCCSStatus::value_type&> {
  GroupSorter(policy::GroupsNames& out_allowed,
              policy::GroupsNames& out_disallowed)
      : out_allowed_(out_allowed), out_disallowed_(out_disallowed) {}

  void operator()(const policy::GroupsByCCSStatus::value_type& value) {
    GroupChecker checker(value.first.status_, out_allowed_, out_disallowed_);
    std::for_each(value.second.begin(), value.second.end(), checker);
  }

 private:
  policy::GroupsNames& out_allowed_;
  policy::GroupsNames& out_disallowed_;
};

}  // namespace

namespace policy {

CREATE_LOGGERPTR_GLOBAL(logger_, "Policy")

#define CACHE_MANAGER_CHECK(return_value)                            \
  {                                                                  \
    if (!pt_) {                                                      \
      LOG4CXX_WARN(logger_, "The cache manager is not initialized"); \
      return return_value;                                           \
    }                                                                \
  }

#define CACHE_MANAGER_CHECK_VOID()                                   \
  {                                                                  \
    if (!pt_) {                                                      \
      LOG4CXX_WARN(logger_, "The cache manager is not initialized"); \
      return;                                                        \
    }                                                                \
  }

struct LanguageFinder {
  explicit LanguageFinder(const std::string& language) : language_(language) {}
  bool operator()(const policy_table::Languages::value_type& lang) const {
    return !strcasecmp(language_.c_str(), lang.first.c_str());
  }

 private:
  const std::string& language_;
};

PolicyManagerImpl::PolicyManagerImpl()
    : PolicyManager()
    , listener_(NULL)
    , retry_sequence_timeout_(60)
    , retry_sequence_index_(0)
    , ignition_check(true)
    , pt_(new policy_table::Table)
    , backup_(new SQLPTExtRepresentation())
    , update_required(false) {
  InitBackupThread();
}

PolicyManagerImpl::PolicyManagerImpl(bool in_memory)
    : PolicyManager()
    , listener_(NULL)
    , retry_sequence_timeout_(60)
    , retry_sequence_index_(0)
    , ignition_check(true)
    , pt_(new policy_table::Table)
    , backup_(new SQLPTExtRepresentation(in_memory))
    , update_required(false) {
  InitBackupThread();
}

PolicyManagerImpl::~PolicyManagerImpl() {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(backuper_locker_);
  backup_thread_->join(threads::Thread::kForceStop);
  delete backup_thread_->delegate();
  threads::DeleteThread(backup_thread_);
}

void PolicyManagerImpl::set_listener(PolicyListener* listener) {
  listener_ = listener;
  update_status_manager_.set_listener(listener);
}

utils::SharedPtr<policy_table::Table> PolicyManagerImpl::Parse(
    const BinaryMessage& pt_content) {
  std::string json(pt_content.begin(), pt_content.end());
  Json::Value value;
  Json::Reader reader;
  if (reader.parse(json.c_str(), value)) {
    return new policy_table::Table(&value);
  } else {
    return utils::SharedPtr<policy_table::Table>();
  }
}

void PolicyManagerImpl::CheckTriggers() {
  LOG4CXX_AUTO_TRACE(logger_);
  const bool exceed_ignition_cycles = ExceededIgnitionCycles();
  const bool exceed_days = ExceededDays();

  LOG4CXX_DEBUG(
      logger_,
      "\nDays exceeded: " << std::boolalpha << exceed_days
                          << "\nIgnition cycles exceeded: " << std::boolalpha
                          << exceed_ignition_cycles);

  if (exceed_ignition_cycles || exceed_days) {
    update_status_manager_.ScheduleUpdate();
  }
}

bool PolicyManagerImpl::LoadPT(const std::string& file,
                               const BinaryMessage& pt_content) {
  LOG4CXX_INFO(logger_, "LoadPT of size " << pt_content.size());
  const std::string empty_certificate;

  // Parse message into table struct
  utils::SharedPtr<policy_table::Table> pt_update = Parse(pt_content);
  if (!pt_update) {
    LOG4CXX_WARN(logger_, "Parsed table pointer is 0.");
    update_status_manager_.OnWrongUpdateReceived();
    listener_->OnCertificateUpdated(empty_certificate);
    return false;
  }

  file_system::DeleteFile(file);

  if (!IsPTValid(pt_update, policy_table::PT_UPDATE)) {
    update_status_manager_.OnWrongUpdateReceived();
    listener_->OnCertificateUpdated(empty_certificate);
    return false;
  }

  update_status_manager_.OnValidUpdateReceived();
  SaveUpdateStatusRequired(false);

  {
    sync_primitives::AutoLock lock(apps_registration_lock_);

    // Get current DB data, since it could be updated during awaiting of PTU
    utils::SharedPtr<policy_table::Table> policy_table_snapshot =
        GenerateSnapshot();
    if (!policy_table_snapshot) {
      LOG4CXX_ERROR(logger_, "Failed to create snapshot of policy table");
      listener_->OnCertificateUpdated(empty_certificate);
      return false;
    }

    // Checking of difference between PTU and current policy state
    // Must to be done before PTU applying since it is possible, that functional
    // groups, which had been present before are absent in PTU and will be
    // removed after update. So in case of revoked groups system has to know
    // names and ids of revoked groups before they will be removed.
    CheckAppPolicyResults results =
        CheckPermissionsChanges(pt_update, policy_table_snapshot);

    {
      // Replace current data with updated
      sync_primitives::AutoLock auto_lock(cache_lock_);
      CACHE_MANAGER_CHECK(false);
      pt_->policy_table.functional_groupings =
          pt_update->policy_table.functional_groupings;

      policy_table::ApplicationPolicies::const_iterator iter =
          pt_update->policy_table.app_policies_section.apps.begin();
      policy_table::ApplicationPolicies::const_iterator iter_end =
          pt_update->policy_table.app_policies_section.apps.end();

      for (; iter != iter_end; ++iter) {
        if (iter->second.is_null()) {
          pt_->policy_table.app_policies_section.apps[iter->first] =
              policy_table::ApplicationParams();
          pt_->policy_table.app_policies_section.apps[iter->first]
              .set_to_null();
          pt_->policy_table.app_policies_section.apps[iter->first]
              .set_to_string("");
        } else if (policy::kDefaultID == (iter->second).get_string()) {
          policy_table::ApplicationPolicies::const_iterator iter_default =
              pt_update->policy_table.app_policies_section.apps.find(
                  kDefaultID);
          if (pt_update->policy_table.app_policies_section.apps.end() ==
              iter_default) {
            LOG4CXX_ERROR(logger_, "The default section was not found in PTU");
            continue;
          }
          ProcessUpdate(iter_default);
        } else {
          ProcessUpdate(iter);
        }
      }

      pt_->policy_table.module_config.SafeCopyFrom(
          pt_update->policy_table.module_config);

      pt_->policy_table.consumer_friendly_messages.assign_if_valid(
          pt_update->policy_table.consumer_friendly_messages);

      ResetCalculatedPermissions();
      Backup();

      if (*pt_->policy_table.module_config.preloaded_pt &&
          pt_update->is_valid()) {
        *pt_->policy_table.module_config.preloaded_pt = false;
      }
    }

    CCSStatus status = GetCCSStatus();
    GroupsByCCSStatus groups_by_status = GetGroupsWithSameEntities(status);

    ProcessCCSStatusUpdate(groups_by_status);

    ProcessAppPolicyCheckResults(
        results, pt_update->policy_table.app_policies_section.apps);

    listener_->OnCertificateUpdated(
        *(pt_update->policy_table.module_config.certificate));

    {
      sync_primitives::AutoLock auto_lock(cache_lock_);
      std::map<std::string, StringArray> app_hmi_types;

      policy_table::ApplicationPolicies::const_iterator policy_iter_begin =
          pt_->policy_table.app_policies_section.apps.begin();
      policy_table::ApplicationPolicies::const_iterator policy_iter_end =
          pt_->policy_table.app_policies_section.apps.end();
      std::vector<std::string> transform_app_hmi_types;
      for (; policy_iter_begin != policy_iter_end; ++policy_iter_begin) {
        const policy_table::ApplicationParams& app_params =
            (*policy_iter_begin).second;
        if (app_params.AppHMIType.is_initialized()) {
          if (!(transform_app_hmi_types.empty())) {
            transform_app_hmi_types.clear();
          }
          std::transform(app_params.AppHMIType->begin(),
                         app_params.AppHMIType->end(),
                         std::back_inserter(transform_app_hmi_types),
                         AppHMITypeToString());
          app_hmi_types[(*policy_iter_begin).first] = transform_app_hmi_types;
        }
      }
      if (!app_hmi_types.empty()) {
        LOG4CXX_INFO(logger_,
                     "app_hmi_types is full calling OnUpdateHMIAppType");
        listener_->OnUpdateHMIAppType(app_hmi_types);
      } else {
        LOG4CXX_INFO(logger_, "app_hmi_types empty" << pt_content.size());
      }
    }
  }

  // If there was a user request for policy table update, it should be started
  // right after current update is finished
  if (update_status_manager_.IsUpdateRequired()) {
    StartPTExchange();
    return true;
  }

  RefreshRetrySequence();
  return true;
}

CheckAppPolicyResults PolicyManagerImpl::CheckPermissionsChanges(
    const utils::SharedPtr<policy_table::Table> pt_update,
    const utils::SharedPtr<policy_table::Table> snapshot) {
  LOG4CXX_INFO(logger_, "Checking incoming permissions.");

  // Replace predefined policies with its actual setting, e.g. "123":"default"
  // to actual values of default section
  UnwrapAppPolicies(pt_update->policy_table.app_policies_section.apps);

  CheckAppPolicyResults out_results;
  std::for_each(pt_update->policy_table.app_policies_section.apps.begin(),
                pt_update->policy_table.app_policies_section.apps.end(),
                CheckAppPolicy(this, pt_update, snapshot, out_results));

  return out_results;
}

void PolicyManagerImpl::ProcessAppPolicyCheckResults(
    const CheckAppPolicyResults& results,
    const policy_table::ApplicationPolicies& app_policies) {
  CheckAppPolicyResults::const_iterator it_results = results.begin();

  for (; results.end() != it_results; ++it_results) {
    const policy_table::ApplicationPolicies::const_iterator app_policy =
        app_policies.find(it_results->first);

    if (app_policies.end() == app_policy) {
      continue;
    }

    if (IsPredefinedApp(*app_policy)) {
      continue;
    }

    switch (it_results->second) {
      case RESULT_NO_CHANGES:
        continue;
      case RESULT_APP_REVOKED:
        NotifySystem(*app_policy);
        continue;
      case RESULT_NICKNAME_MISMATCH:
        NotifySystem(*app_policy);
        continue;
      case RESULT_CONSENT_NEEDED:
      case RESULT_PERMISSIONS_REVOKED_AND_CONSENT_NEEDED: {
        // Post-check after CCS consent changes
        const std::string policy_app_id = app_policy->first;
        if (!IsConsentNeeded(policy_app_id)) {
          sync_primitives::AutoLock lock(app_permissions_diff_lock_);

          PendingPermissions::iterator app_id_diff =
              app_permissions_diff_.find(policy_app_id);

          if (app_permissions_diff_.end() != app_id_diff) {
            app_id_diff->second.appPermissionsConsentNeeded = false;
          }
        }
      } break;
      case RESULT_CONSENT_NOT_REQIURED:
      case RESULT_PERMISSIONS_REVOKED:
      case RESULT_REQUEST_TYPE_CHANGED:
        break;
      default:
        continue;
    }
    NotifySystem(*app_policy);
    SendPermissionsToApp(*app_policy);
  }
}

void PolicyManagerImpl::PrepareNotificationData(
    const policy_table::FunctionalGroupings& groups,
    const policy_table::Strings& group_names,
    const std::vector<FunctionalGroupPermission>& group_permission,
    Permissions& notification_data) {
  LOG4CXX_INFO(logger_, "Preparing data for notification.");
  ProcessFunctionalGroup processor(groups, group_permission, notification_data);
  std::for_each(group_names.begin(), group_names.end(), processor);
}

std::string PolicyManagerImpl::GetUpdateUrl(int service_type) const {
  LOG4CXX_AUTO_TRACE(logger_);
  EndpointUrls urls;
  GetUpdateUrls(service_type, urls);

  std::string url;
  if (!urls.empty()) {
    static uint32_t index = 0;

    if (!urls.empty() && index >= urls.size()) {
      index = 0;
    }
    url = urls[index].url.empty() ? "" : urls[index].url[0];

    ++index;
  } else {
    LOG4CXX_ERROR(logger_, "The endpoint entry is empty");
  }
  return url;
}

void PolicyManagerImpl::GetUpdateUrls(int service_type,
                                      EndpointUrls& end_points) const {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  char buff[32];
  sprintf(buff, "%x", service_type);

  std::string serv_type(buff);
  // TODO: remove this workaround
  if (service_type <= 0x9) {
    serv_type.insert(0, "0x0", 3);
  } else {
    serv_type.insert(0, "0x", 2);
  }

  policy_table::ServiceEndpoints::const_iterator iter =
      pt_->policy_table.module_config.endpoints.find(serv_type);

  if (pt_->policy_table.module_config.endpoints.end() != iter) {
    policy_table::URLList::const_iterator url_list_iter =
        (*iter).second.begin();
    policy_table::URLList::const_iterator url_list_iter_end =
        (*iter).second.end();
    for (; url_list_iter != url_list_iter_end; ++url_list_iter) {
      EndpointData data;
      data.app_id = (*url_list_iter).first;
      std::copy((*url_list_iter).second.begin(),
                (*url_list_iter).second.end(),
                std::back_inserter(data.url));

      end_points.push_back(data);
    }
  }
}

void PolicyManagerImpl::RequestPTUpdate() {
  LOG4CXX_AUTO_TRACE(logger_);
  utils::SharedPtr<policy_table::Table> policy_table_snapshot =
      GenerateSnapshot();
  if (!policy_table_snapshot) {
    LOG4CXX_ERROR(logger_, "Failed to create snapshot of policy table");
    return;
  }

  if (IsPTValid(policy_table_snapshot, policy_table::PT_SNAPSHOT)) {
    Json::Value value = policy_table_snapshot->ToJsonValue();
    Json::FastWriter writer;
    std::string message_string = writer.write(value);

    LOG4CXX_DEBUG(logger_, "Snapshot contents is : " << message_string);

    BinaryMessage update(message_string.begin(), message_string.end());

    listener_->OnSnapshotCreated(
        update, RetrySequenceDelaysSeconds(), TimeoutExchange());

    // Need to reset update schedule since all currently registered applications
    // were already added to the snapshot so no update for them required.
    update_status_manager_.ResetUpdateSchedule();
  } else {
    LOG4CXX_ERROR(logger_, "Invalid Policy table snapshot - PTUpdate failed");
  }
}

void PolicyManagerImpl::StartPTExchange() {
  LOG4CXX_AUTO_TRACE(logger_);

  if (ignition_check) {
    CheckTriggers();
    ignition_check = false;
  }

  if (update_status_manager_.IsAppsSearchInProgress() &&
      update_status_manager_.IsUpdateRequired()) {
    LOG4CXX_INFO(logger_,
                 "Starting exchange skipped, since applications "
                 "search is in progress.");
    return;
  }

  if (update_status_manager_.IsUpdatePending()) {
    update_status_manager_.ScheduleUpdate();
    LOG4CXX_INFO(logger_,
                 "Starting exchange skipped, since another exchange "
                 "is in progress.");
    return;
  }

  if (listener_ && listener_->CanUpdate()) {
    if (update_status_manager_.IsUpdateRequired()) {
      RequestPTUpdate();
    }
  }
}

void PolicyManagerImpl::OnAppsSearchStarted() {
  LOG4CXX_AUTO_TRACE(logger_);
  update_status_manager_.OnAppsSearchStarted();
}

void PolicyManagerImpl::OnAppsSearchCompleted() {
  LOG4CXX_AUTO_TRACE(logger_);
  update_status_manager_.OnAppsSearchCompleted();
  if (update_status_manager_.IsUpdateRequired()) {
    StartPTExchange();
  }
}

const std::vector<std::string> PolicyManagerImpl::GetAppRequestTypes(
    const std::string policy_app_id) const {
  LOG4CXX_AUTO_TRACE(logger_);
  std::vector<std::string> request_types;
  CACHE_MANAGER_CHECK(request_types);
  std::string app_id = policy_app_id;

  if (kDeviceDisallowed ==
      GetDeviceConsent(GetCurrentDeviceId(policy_app_id))) {
    app_id = kPreDataConsentId;
  }

  policy_table::ApplicationPolicies::iterator policy_iter =
      pt_->policy_table.app_policies_section.apps.find(app_id);
  if (pt_->policy_table.app_policies_section.apps.end() == policy_iter) {
    LOG4CXX_DEBUG(logger_, "Can't find request types for app_id " << app_id);
    return request_types;
  }
  if (policy_iter->second.RequestType.is_initialized()) {
    policy_table::RequestTypes::iterator it_request_type =
        policy_iter->second.RequestType->begin();
    for (; it_request_type != policy_iter->second.RequestType->end();
         ++it_request_type) {
      request_types.push_back(EnumToJsonString(*it_request_type));
    }
  }

  return request_types;
}

const VehicleInfo PolicyManagerImpl::GetVehicleInfo() const {
  CACHE_MANAGER_CHECK(VehicleInfo());
  policy_table::ModuleConfig& module_config = pt_->policy_table.module_config;
  VehicleInfo vehicle_info;
  vehicle_info.vehicle_make = *module_config.vehicle_make;
  vehicle_info.vehicle_model = *module_config.vehicle_model;
  vehicle_info.vehicle_year = *module_config.vehicle_year;
  LOG4CXX_DEBUG(
      logger_,
      "Vehicle info (make, model, year):" << vehicle_info.vehicle_make << ","
                                          << vehicle_info.vehicle_model << ","
                                          << vehicle_info.vehicle_year);
  return vehicle_info;
}

void PolicyManagerImpl::CheckPermissions(const PTString& app_id,
                                         const PTString& hmi_level,
                                         const PTString& rpc,
                                         const RPCParams& rpc_params,
                                         CheckPermissionResult& result) {
  LOG4CXX_INFO(logger_,
               "CheckPermissions for " << app_id << " and rpc " << rpc
                                       << " for " << hmi_level << " level.");

  const std::string device_id = GetCurrentDeviceId(app_id);

  Permissions rpc_permissions;

  // Check, if there are calculated permission present in cache
  if (!IsPermissionsCalculated(device_id, app_id, rpc_permissions)) {
    LOG4CXX_DEBUG(logger_,
                  "IsPermissionsCalculated for device: "
                      << device_id << " and app: " << app_id
                      << " returns false");
    // Get actual application group permission according to user consents
    std::vector<FunctionalGroupPermission> app_group_permissions;
    GetPermissionsForApp(device_id, app_id, app_group_permissions);

    // Fill struct with known groups RPCs
    policy_table::FunctionalGroupings functional_groupings;
    GetFunctionalGroupings(functional_groupings);

    policy_table::Strings app_groups = GetGroupsNames(app_group_permissions);

    // Undefined groups (without user consent) disallowed by default, since
    // OnPermissionsChange notification has no "undefined" section
    // For RPC permission checking undefinded group will be treated as separate
    // type
    ProcessFunctionalGroup processor(functional_groupings,
                                     app_group_permissions,
                                     rpc_permissions,
                                     GroupConsent::kGroupUndefined);
    std::for_each(app_groups.begin(), app_groups.end(), processor);

    AddCalculatedPermissions(device_id, app_id, rpc_permissions);
  } else {
    LOG4CXX_DEBUG(logger_,
                  "IsPermissionsCalculated for device: "
                      << device_id << " and app: " << app_id
                      << " returns true");
  }

  const bool known_rpc = rpc_permissions.end() != rpc_permissions.find(rpc);
  LOG4CXX_INFO(logger_, "Is known rpc " << known_rpc);
  if (!known_rpc) {
    // RPC not found in list == disallowed by backend
    result.hmi_level_permitted = kRpcDisallowed;
    return;
  }

  // Check HMI level
  if (rpc_permissions[rpc].hmi_permissions[kAllowedKey].end() !=
      rpc_permissions[rpc].hmi_permissions[kAllowedKey].find(hmi_level)) {
    // RPC found in allowed == allowed by backend and user
    result.hmi_level_permitted = kRpcAllowed;
  } else if (rpc_permissions[rpc].hmi_permissions[kUndefinedKey].end() !=
             rpc_permissions[rpc].hmi_permissions[kUndefinedKey].find(
                 hmi_level)) {
    // RPC found in undefined == allowed by backend, but not consented yet by
    // user
    result.hmi_level_permitted = kRpcDisallowed;
  } else if (rpc_permissions[rpc].hmi_permissions[kUserDisallowedKey].end() !=
             rpc_permissions[rpc].hmi_permissions[kUserDisallowedKey].find(
                 hmi_level)) {
    // RPC found in allowed == allowed by backend, but disallowed by user
    result.hmi_level_permitted = kRpcUserDisallowed;
  } else {
    LOG4CXX_DEBUG(logger_,
                  "HMI level " << hmi_level << " wasn't found "
                               << " for rpc " << rpc << " and appID "
                               << app_id);
    return;
  }

  if (kRpcAllowed != result.hmi_level_permitted) {
    LOG4CXX_DEBUG(logger_, "RPC is not allowed. Stop parameters processing.");
    result.list_of_allowed_params =
        rpc_permissions[rpc].parameter_permissions[kAllowedKey];

    result.list_of_disallowed_params =
        rpc_permissions[rpc].parameter_permissions[kUserDisallowedKey];

    result.list_of_undefined_params =
        rpc_permissions[rpc].parameter_permissions[kUndefinedKey];
    return;
  }

  // Considered that items disallowed by user take priority over system (policy)
  // permissions, so that flag is processed first
  if (rpc_permissions[rpc]
          .parameter_permissions.any_parameter_disallowed_by_user) {
    LOG4CXX_DEBUG(logger_, "All parameters are disallowed by user.");
    result.list_of_disallowed_params = rpc_params;
    result.hmi_level_permitted = kRpcUserDisallowed;
    return;
  }

  if (rpc_permissions[rpc]
          .parameter_permissions.any_parameter_disallowed_by_policy) {
    LOG4CXX_DEBUG(logger_, "All parameters are disallowed by policy.");
    result.list_of_undefined_params = rpc_params;
    result.hmi_level_permitted = kRpcDisallowed;
    return;
  }

  if (rpc_permissions[rpc].parameter_permissions.any_parameter_allowed) {
    LOG4CXX_DEBUG(logger_, "All parameters are allowed.");
    result.list_of_allowed_params = rpc_params;
    return;
  }

  result.list_of_allowed_params =
      rpc_permissions[rpc].parameter_permissions[kAllowedKey];

  result.list_of_disallowed_params =
      rpc_permissions[rpc].parameter_permissions[kUserDisallowedKey];

  result.list_of_undefined_params =
      rpc_permissions[rpc].parameter_permissions[kUndefinedKey];

  // In case of some parameters of RPC are missing in current policy table
  // they will be considered as disallowed by policy itself, not by user.
  // Undefined parameters contain parameters present in policy table, but which
  // have not been allowed or disallowed explicitly by user, so missing params
  // are being added to undefined.
  RPCParams::const_iterator parameter = rpc_params.begin();
  RPCParams::const_iterator end = rpc_params.end();
  for (; end != parameter; ++parameter) {
    if (!result.HasParameter(*parameter)) {
      LOG4CXX_DEBUG(logger_,
                    "Parameter " << *parameter << " is unknown."
                                                  " Adding to undefined list.");
      result.list_of_undefined_params.insert(*parameter);
    }
  }

  if (result.DisallowedInclude(rpc_params)) {
    LOG4CXX_DEBUG(logger_, "All parameters are disallowed.");
    result.hmi_level_permitted = kRpcUserDisallowed;
  } else if (!result.IsAnyAllowed(rpc_params)) {
    LOG4CXX_DEBUG(logger_, "There are no parameters allowed.");
    result.hmi_level_permitted = kRpcDisallowed;
  }

  if (IsApplicationRevoked(app_id)) {
    // SDL must be able to notify mobile side with its status after app has
    // been revoked by backend
    if ("OnHMIStatus" == rpc && "NONE" == hmi_level) {
      result.hmi_level_permitted = kRpcAllowed;
    } else {
      result.hmi_level_permitted = kRpcDisallowed;
    }
    return;
  }
}

bool PolicyManagerImpl::ResetUserConsent() {
  sync_primitives::AutoLock lock(cache_lock_);
  CACHE_MANAGER_CHECK(false);
  policy_table::DeviceData::iterator iter =
      pt_->policy_table.device_data->begin();
  policy_table::DeviceData::iterator iter_end =
      pt_->policy_table.device_data->end();

  for (; iter != iter_end; ++iter) {
    iter->second.user_consent_records->clear();
  }

  return true;
}

policy_table::Strings PolicyManagerImpl::GetGroupsNames(
    const std::vector<FunctionalGroupPermission>& app_group_permissions) const {
  policy_table::Strings app_groups;
  GroupNamesAppender appender(app_groups);
  std::for_each(
      app_group_permissions.begin(), app_group_permissions.end(), appender);

  return app_groups;
}

void PolicyManagerImpl::SendNotificationOnPermissionsUpdated(
    const std::string& application_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  const std::string device_id = GetCurrentDeviceId(application_id);
  if (device_id.empty()) {
    LOG4CXX_WARN(logger_,
                 "Couldn't find device info for application id "
                 "'" << application_id << "'");
    return;
  }

  std::vector<FunctionalGroupPermission> app_group_permissions;
  GetPermissionsForApp(device_id, application_id, app_group_permissions);

  policy_table::FunctionalGroupings functional_groupings;
  GetFunctionalGroupings(functional_groupings);

  policy_table::Strings app_groups = GetGroupsNames(app_group_permissions);

  Permissions notification_data;
  PrepareNotificationData(functional_groupings,
                          app_groups,
                          app_group_permissions,
                          notification_data);

  LOG4CXX_INFO(logger_,
               "Send notification for application_id:" << application_id);

  std::string default_hmi;
  GetDefaultHmi(application_id, &default_hmi);

  listener()->OnPermissionsUpdated(
      application_id, notification_data, default_hmi);
}

bool PolicyManagerImpl::CleanupUnpairedDevices() {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  sync_primitives::AutoLock lock(cache_lock_);
  sync_primitives::AutoLock lock_unpaired(unpaired_lock_);
  UnpairedDevices::iterator iter = is_unpaired_.begin();
  UnpairedDevices::const_iterator iter_end = is_unpaired_.end();
  LOG4CXX_DEBUG(logger_, "Is_unpaired size is: " << is_unpaired_.size());
  for (; iter != iter_end; ++iter) {
    // Delete device
    if (!pt_->policy_table.device_data.is_initialized()) {
      LOG4CXX_ERROR(logger_, "Device_data section is not initialized.");
      return false;
    }
    policy_table::DeviceData& device_data = *pt_->policy_table.device_data;
    policy_table::DeviceData::iterator it_device = device_data.find(*iter);
    if (device_data.end() == it_device) {
      LOG4CXX_INFO(logger_,
                   "No device id "
                       << *iter << " had been found in device_data section.");
      return false;
    }

    LOG4CXX_DEBUG(logger_, "Device_data size is: " << device_data.size());
    device_data.erase(it_device);
    LOG4CXX_INFO(logger_,
                 "Device id " << *iter
                              << " had been deleted from device_data section.");
    LOG4CXX_DEBUG(logger_, "Device_data size is: " << device_data.size());
  }
  is_unpaired_.clear();
  Backup();
  return true;
}

DeviceConsent PolicyManagerImpl::GetUserConsentForDevice(
    const std::string& device_id) const {
  LOG4CXX_AUTO_TRACE(logger_);
  return GetDeviceConsent(device_id);
}

std::vector<std::string> PolicyManagerImpl::GetDevicesIDs() const {
  LOG4CXX_AUTO_TRACE(logger_);
  std::vector<std::string> result;
  CACHE_MANAGER_CHECK(result);
  policy_table::DeviceData::const_iterator iter =
      pt_->policy_table.device_data->begin();
  const policy_table::DeviceData::const_iterator iter_end =
      pt_->policy_table.device_data->end();
  for (; iter != iter_end; ++iter) {
    result.push_back(iter->first);
  }
  return result;
}

rpc::policy_table_interface_base::UserSetting
PolicyManagerImpl::GetDeviceUSBTransportStatus(
    const std::string& device_id) const {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(policy_table::UserSetting::DISABLED);

  policy_table::DeviceData& device_data = *pt_->policy_table.device_data;
  policy_table::DeviceData::const_iterator device_data_iter =
      device_data.find(device_id);
  if (device_data.end() == device_data_iter) {
    LOG4CXX_ERROR(logger_,
                  "Device with " << device_id << " was not found in PT");
    return policy_table::UserSetting::DISABLED;
  }

  const policy_table::DeviceParams& params = device_data_iter->second;
  const policy_table::UserSetting usb_transport_status =
      *(params.usb_transport_status);
  return usb_transport_status;
}

bool PolicyManagerImpl::GetDeviceConnectionType(
    const std::string& device_id, std::string& out_connection_type) const {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);

  policy_table::DeviceData& device_data = *pt_->policy_table.device_data;
  policy_table::DeviceData::const_iterator device_data_iter =
      device_data.find(device_id);
  if (device_data.end() == device_data_iter) {
    LOG4CXX_ERROR(logger_,
                  "Device with " << device_id << " was not found in PT");
    out_connection_type.clear();
    return false;
  }

  const policy_table::DeviceParams& params = device_data_iter->second;
  out_connection_type = *(params.connection_type);
  return true;
}

void PolicyManagerImpl::SetUserConsentForDevice(const std::string& device_id,
                                                const bool is_allowed) {
  LOG4CXX_AUTO_TRACE(logger_);
  LOG4CXX_DEBUG(logger_, "Device :" << device_id);
  CACHE_MANAGER_CHECK_VOID();

  if (HasDeviceSpecifiedConsent(device_id, is_allowed)) {
    return;
  }
  ResetCalculatedPermissionsForDevice(device_id);
  // Remove unpaired mark, if device re-paired and re-consented again
  if (is_allowed) {
    SetUnpairedDevice(device_id, false);
  }

  StringArray list_of_permissions;
  if (!GetPermissionsList(list_of_permissions) || list_of_permissions.empty()) {
    LOG4CXX_WARN(logger_, "List of permissions can't be received or empty");
    return;
  }

  StringArray consented_groups;
  StringArray disallowed_groups;

  // Supposed only one group for device date consent
  if (is_allowed) {
    consented_groups = list_of_permissions;
  } else {
    disallowed_groups = list_of_permissions;
  }

  if (!SetUserPermissionsForDevice(
          device_id, consented_groups, disallowed_groups)) {
    LOG4CXX_WARN(logger_, "Can't set user consent for device");
    return;
  }

  SaveDeviceConsentToCache(device_id, is_allowed);

  if (listener_) {
    listener_->OnDeviceConsentChanged(device_id, is_allowed);
  } else {
    LOG4CXX_WARN(logger_,
                 "Event listener is not initialized. "
                 "Can't call OnDeviceConsentChanged");
  }
  StartPTExchange();
}

bool PolicyManagerImpl::ReactOnUserDevConsentForApp(
    const std::string& app_id, const bool is_device_allowed) {
  std::vector<std::string> current_request_types = GetAppRequestTypes(app_id);
  std::string current_priority, new_priority;
  GetPriority(app_id, &current_priority);

  bool result = true;
  {
    sync_primitives::AutoLock auto_lock(cache_lock_);
    CACHE_MANAGER_CHECK(false);

    if (is_device_allowed) {
      // If app has pre_DataConsented groups it should be 'promoted' to default
      if (IsPredataPolicy(app_id)) {
        result = SetDefaultPolicy(app_id);
      }
    } else {
      if (IsApplicationRepresented(app_id)) {
        pt_->policy_table.app_policies_section.apps[app_id].set_to_string(
            kPreDataConsentId);
      }
    }
  }
  Backup();

  std::vector<std::string> new_request_types = GetAppRequestTypes(app_id);
  GetPriority(app_id, &new_priority);
  std::sort(current_request_types.begin(), current_request_types.end());
  std::sort(new_request_types.begin(), new_request_types.end());

  std::vector<std::string> diff;
  std::set_symmetric_difference(current_request_types.begin(),
                                current_request_types.end(),
                                new_request_types.begin(),
                                new_request_types.end(),
                                std::back_inserter(diff));

  AppPermissions permissions(app_id);

  if (!diff.empty()) {
    permissions.requestType = new_request_types;
    permissions.requestTypeChanged = true;
  }

  if ((!current_priority.empty()) && (!new_priority.empty()) &&
      (current_priority != new_priority)) {
    permissions.priority = new_priority;
  }

  if (permissions.requestTypeChanged || (!permissions.priority.empty())) {
    listener_->SendOnAppPermissionsChanged(permissions, app_id);
  }
  return result;
}

bool PolicyManagerImpl::GetInitialAppData(const std::string& application_id,
                                          StringArray* nicknames,
                                          StringArray* app_hmi_types) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  const bool result = nicknames && app_hmi_types;
  if (result) {
    policy_table::ApplicationPolicies::const_iterator policy_iter =
        pt_->policy_table.app_policies_section.apps.find(application_id);

    if (pt_->policy_table.app_policies_section.apps.end() != policy_iter) {
      const policy_table::ApplicationParams& app_params = (*policy_iter).second;

      std::copy(app_params.nicknames->begin(),
                app_params.nicknames->end(),
                std::back_inserter(*nicknames));

      std::transform(app_params.AppHMIType->begin(),
                     app_params.AppHMIType->end(),
                     std::back_inserter(*app_hmi_types),
                     AppHMITypeToString());
    }
  }
  return result;
}

void PolicyManagerImpl::AddDevice(const std::string& device_id,
                                  const std::string& connection_type) {
  LOG4CXX_AUTO_TRACE(logger_);
  LOG4CXX_DEBUG(logger_, "Device: " << device_id);
  sync_primitives::AutoLock auto_lock(cache_lock_);
  CACHE_MANAGER_CHECK_VOID();
  policy_table::DeviceParams& params =
      (*(pt_->policy_table.device_data))[device_id];
  *params.connection_type = connection_type;

  // We have to set preloaded flag as false in policy table on adding new
  // information (SDLAQ-CRS-2365). It can happens only after device addition.
  *pt_->policy_table.module_config.preloaded_pt = false;

  Backup();
}

void PolicyManagerImpl::SetDeviceInfo(const std::string& device_id,
                                      const DeviceInfo& device_info) {
  LOG4CXX_AUTO_TRACE(logger_);
  LOG4CXX_DEBUG(logger_, "Device :" << device_id);
  sync_primitives::AutoLock auto_lock(cache_lock_);
  CACHE_MANAGER_CHECK_VOID();

  if (pt_->policy_table.device_data->end() ==
      pt_->policy_table.device_data->find(device_id)) {
    LOG4CXX_ERROR(
        logger_,
        "Can't set device data. Unable to find mobile device: " << device_id);
    return;
  }

  policy_table::DeviceParams& params =
      (*(pt_->policy_table.device_data))[device_id];
  *params.hardware = device_info.hardware;
  *params.firmware_rev = device_info.firmware_rev;
  *params.os = device_info.os;
  *params.os_version = device_info.os_ver;
  *params.carrier = device_info.carrier;
  *params.max_number_rfcom_ports = device_info.max_number_rfcom_ports;
  *params.connection_type = device_info.connection_type;
  *params.usb_transport_status = device_info.usb_transport_status;

  Backup();
}

void PolicyManagerImpl::UpdateConnectionStatus(
    const std::string& device_id,
    const policy_table::UserSetting usb_transport_status) {
  LOG4CXX_AUTO_TRACE(logger_);
  LOG4CXX_DEBUG(logger_, "Device :" << device_id);
  sync_primitives::AutoLock auto_lock(cache_lock_);
  CACHE_MANAGER_CHECK_VOID();

  if (pt_->policy_table.device_data->end() ==
      pt_->policy_table.device_data->find(device_id)) {
    LOG4CXX_ERROR(logger_, "Unable to find mobile device: " << device_id);
    return;
  }

  policy_table::DeviceParams& params =
      (*(pt_->policy_table.device_data))[device_id];
  *params.usb_transport_status = usb_transport_status;

  Backup();
}

PermissionConsent PolicyManagerImpl::EnsureCorrectPermissionConsent(
    const PermissionConsent& permissions_to_check) {
  std::vector<FunctionalGroupPermission> current_user_consents;
  GetUserConsentForApp(permissions_to_check.device_id,
                       permissions_to_check.policy_app_id,
                       current_user_consents);

  PermissionConsent permissions_to_set;
  permissions_to_set.device_id = permissions_to_check.device_id;
  permissions_to_set.policy_app_id = permissions_to_check.policy_app_id;
  permissions_to_set.consent_source = permissions_to_check.consent_source;

  std::vector<FunctionalGroupPermission>::const_iterator it =
      permissions_to_check.group_permissions.begin();
  std::vector<FunctionalGroupPermission>::const_iterator it_end =
      permissions_to_check.group_permissions.end();

  for (; it != it_end; ++it) {
    std::vector<FunctionalGroupPermission>::const_iterator it_curr =
        current_user_consents.begin();
    std::vector<FunctionalGroupPermission>::const_iterator it_curr_end =
        current_user_consents.end();

    for (; it_curr != it_curr_end; ++it_curr) {
      if (it->group_alias == it_curr->group_alias &&
          it->group_id == it_curr->group_id) {
        permissions_to_set.group_permissions.push_back(*it);
      }
    }
  }

  return permissions_to_set;
}

void PolicyManagerImpl::CheckPendingPermissionsChanges(
    const std::string& policy_app_id,
    const std::vector<FunctionalGroupPermission>& current_permissions) {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(app_permissions_diff_lock_);
  PendingPermissions::iterator it_pending =
      app_permissions_diff_.find(policy_app_id);
  if (app_permissions_diff_.end() == it_pending) {
    LOG4CXX_WARN(
        logger_,
        "No pending permissions had been found for appID: " << policy_app_id);
    return;
  }

  LOG4CXX_DEBUG(
      logger_,
      "Pending permissions had been found for appID: " << policy_app_id);

  // Change appPermissionsConsentNeeded depending on unconsented groups
  // presence
  std::vector<policy::FunctionalGroupPermission>::const_iterator it_groups =
      current_permissions.begin();
  std::vector<policy::FunctionalGroupPermission>::const_iterator it_end_groups =
      current_permissions.end();

  for (; it_groups != it_end_groups; ++it_groups) {
    if (policy::kGroupUndefined == it_groups->state) {
      LOG4CXX_DEBUG(
          logger_,
          "Unconsented groups still present for appID: " << policy_app_id);
      it_pending->second.appPermissionsConsentNeeded = true;
      return;
    }
  }

  LOG4CXX_DEBUG(
      logger_,
      "Unconsented groups not present anymore for appID: " << policy_app_id);
  it_pending->second.appPermissionsConsentNeeded = false;
  return;
}

void PolicyManagerImpl::NotifyPermissionsChanges(
    const std::string& policy_app_id,
    const std::vector<FunctionalGroupPermission>& app_group_permissions) {
  // Get current functional groups from DB with RPC permissions
  policy_table::FunctionalGroupings functional_groups;
  GetFunctionalGroupings(functional_groups);

  // Get list of groups assigned to application
  policy_table::Strings app_groups = GetGroupsNames(app_group_permissions);

  // Fill notification data according to group permissions
  Permissions notification_data;
  PrepareNotificationData(
      functional_groups, app_groups, app_group_permissions, notification_data);

  listener()->OnPermissionsUpdated(policy_app_id, notification_data);
}

void PolicyManagerImpl::SetUserConsentForApp(
    const PermissionConsent& permissions) {
  LOG4CXX_AUTO_TRACE(logger_);
  ResetCalculatedPermissions();
  PermissionConsent verified_permissions =
      EnsureCorrectPermissionConsent(permissions);

  sync_primitives::AutoLock auto_lock(cache_lock_);
  CACHE_MANAGER_CHECK_VOID();
  std::vector<FunctionalGroupPermission>::const_iterator iter =
      verified_permissions.group_permissions.begin();
  std::vector<FunctionalGroupPermission>::const_iterator iter_end =
      verified_permissions.group_permissions.end();

  std::string group_name;

  // set user permissions for app:
  for (; iter != iter_end; ++iter) {
    if (policy::kGroupUndefined != (*iter).state) {
      policy_table::DeviceParams& params =
          (*pt_->policy_table.device_data)[verified_permissions.device_id];
      rpc::policy_table_interface_base::ConsentRecords& ucr =
          (*params.user_consent_records)[verified_permissions.policy_app_id];

      GetGroupNameByHashID((*iter).group_id, group_name);

      (*ucr.consent_groups)[group_name] =
          ((*iter).state == policy::kGroupAllowed);
      *ucr.input = policy_table::Input::I_GUI;
      *ucr.time_stamp = currentDateTime();
    }
  }

  Backup();

  std::vector<FunctionalGroupPermission> updated_app_group_permissons;
  GetPermissionsForApp(verified_permissions.device_id,
                       verified_permissions.policy_app_id,
                       updated_app_group_permissons);

  CheckPendingPermissionsChanges(verified_permissions.policy_app_id,
                                 updated_app_group_permissons);

  NotifyPermissionsChanges(verified_permissions.policy_app_id,
                           updated_app_group_permissons);
}

bool PolicyManagerImpl::GetDefaultHmi(const std::string& policy_app_id,
                                      std::string* default_hmi) const {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  const std::string device_id = GetCurrentDeviceId(policy_app_id);
  DeviceConsent device_consent = GetUserConsentForDevice(device_id);
  const std::string app_id = policy::kDeviceAllowed != device_consent
                                 ? kPreDataConsentId
                                 : policy_app_id;
  default_hmi->clear();
  if (kDeviceID == app_id) {
    *default_hmi = EnumToJsonString(
        pt_->policy_table.app_policies_section.device.default_hmi);
  } else if (IsApplicationRepresented(app_id)) {
    *default_hmi = EnumToJsonString(
        pt_->policy_table.app_policies_section.apps[app_id].default_hmi);
  }
  return !default_hmi->empty();
}

bool PolicyManagerImpl::GetPriority(const std::string& policy_app_id,
                                    std::string* priority) const {
  LOG4CXX_AUTO_TRACE(logger_);
  if (!priority) {
    LOG4CXX_WARN(logger_, "Input priority parameter is null.");
    return false;
  }
  CACHE_MANAGER_CHECK(false);
  if (kDeviceID == policy_app_id) {
    *priority = EnumToJsonString(
        pt_->policy_table.app_policies_section.device.priority);
    return true;
  }

  const policy_table::ApplicationPolicies& policies =
      pt_->policy_table.app_policies_section.apps;

  policy_table::ApplicationPolicies::const_iterator policy_iter =
      policies.find(policy_app_id);
  const bool app_id_exists = policies.end() != policy_iter;
  if (app_id_exists) {
    *priority = EnumToJsonString((*policy_iter).second.priority);
  }

  return app_id_exists;
}

std::vector<UserFriendlyMessage> PolicyManagerImpl::GetUserFriendlyMessages(
    const std::vector<std::string>& message_codes,
    const std::string& language) {
  LOG4CXX_AUTO_TRACE(logger_);
  std::vector<UserFriendlyMessage> result;
  CACHE_MANAGER_CHECK(result);

  std::vector<std::string>::const_iterator it = message_codes.begin();
  std::vector<std::string>::const_iterator it_end = message_codes.end();
  for (; it != it_end; ++it) {
    policy_table::MessageLanguages msg_languages =
        (*pt_->policy_table.consumer_friendly_messages->messages)[*it];

    policy_table::MessageString message_string;

    // If message has no records with required language, fallback language
    // should be used instead.
    LanguageFinder finder(language);
    policy_table::Languages::const_iterator it_language = std::find_if(
        msg_languages.languages.begin(), msg_languages.languages.end(), finder);

    if (msg_languages.languages.end() == it_language) {
      LOG4CXX_WARN(logger_,
                   "Language "
                       << language
                       << " haven't been found for message code: " << *it);

      LanguageFinder fallback_language_finder("en-us");

      policy_table::Languages::const_iterator it_fallback_language =
          std::find_if(msg_languages.languages.begin(),
                       msg_languages.languages.end(),
                       fallback_language_finder);

      if (msg_languages.languages.end() == it_fallback_language) {
        LOG4CXX_ERROR(logger_,
                      "No fallback language found for message code: " << *it);
        continue;
      }

      message_string = it_fallback_language->second;
    } else {
      message_string = it_language->second;
    }

    UserFriendlyMessage msg;
    msg.message_code = *it;
    msg.tts = *message_string.tts;
    msg.label = *message_string.label;
    msg.line1 = *message_string.line1;
    msg.line2 = *message_string.line2;
    msg.text_body = *message_string.textBody;

    result.push_back(msg);
  }
  return result;
}

void PolicyManagerImpl::GetUserConsentForApp(
    const std::string& device_id,
    const std::string& policy_app_id,
    std::vector<FunctionalGroupPermission>& permissions) {
  LOG4CXX_AUTO_TRACE(logger_);

  FunctionalIdType group_types;
  if (!GetPermissionsForApp(device_id, policy_app_id, group_types)) {
    LOG4CXX_WARN(logger_,
                 "Can't get user permissions for app " << policy_app_id);
    return;
  }

  // Functional groups w/o alias ("user_consent_prompt") considered as
  // automatically allowed and it could not be changed by user
  FunctionalGroupNames group_names;
  if (!GetFunctionalGroupNames(group_names)) {
    LOG4CXX_WARN(logger_, "Can't get functional group names");
    return;
  }

  FunctionalGroupNames::const_iterator it = group_names.begin();
  FunctionalGroupNames::const_iterator it_end = group_names.end();
  FunctionalGroupIDs auto_allowed_groups;
  for (; it != it_end; ++it) {
    if (it->second.first.empty()) {
      auto_allowed_groups.push_back(it->first);
    }
  }

  FunctionalGroupIDs all_groups = group_types[kTypeGeneral];
  FunctionalGroupIDs preconsented_groups = group_types[kTypePreconsented];
  FunctionalGroupIDs consent_allowed_groups = group_types[kTypeAllowed];
  FunctionalGroupIDs consent_disallowed_groups = group_types[kTypeDisallowed];
  FunctionalGroupIDs default_groups = group_types[kTypeDefault];
  FunctionalGroupIDs predataconsented_groups =
      group_types[kTypePreDataConsented];
  FunctionalGroupIDs device_groups = group_types[kTypeDevice];

  // Sorting groups by consent
  FunctionalGroupIDs preconsented_wo_auto =
      ExcludeSame(preconsented_groups, auto_allowed_groups);

  FunctionalGroupIDs preconsented_wo_disallowed_auto =
      ExcludeSame(preconsented_wo_auto, consent_disallowed_groups);

  FunctionalGroupIDs allowed_groups =
      Merge(consent_allowed_groups, preconsented_wo_disallowed_auto);

  FunctionalGroupIDs merged_stage_1 =
      Merge(default_groups, predataconsented_groups);

  FunctionalGroupIDs merged_stage_2 = Merge(merged_stage_1, device_groups);

  FunctionalGroupIDs merged_stage_3 =
      Merge(merged_stage_2, auto_allowed_groups);

  FunctionalGroupIDs excluded_stage_1 = ExcludeSame(all_groups, merged_stage_3);

  FunctionalGroupIDs excluded_stage_2 =
      ExcludeSame(excluded_stage_1, consent_disallowed_groups);

  FunctionalGroupIDs undefined_consent =
      ExcludeSame(excluded_stage_2, allowed_groups);

  // Fill result
  FillFunctionalGroupPermissions(
      undefined_consent, group_names, kGroupUndefined, permissions);
  FillFunctionalGroupPermissions(
      allowed_groups, group_names, kGroupAllowed, permissions);
  FillFunctionalGroupPermissions(
      consent_disallowed_groups, group_names, kGroupDisallowed, permissions);
}

void PolicyManagerImpl::GetPermissionsForApp(
    const std::string& device_id,
    const std::string& policy_app_id,
    std::vector<FunctionalGroupPermission>& permissions) {
  LOG4CXX_AUTO_TRACE(logger_);
  std::string app_id_to_check = policy_app_id;

  if (!IsApplicationRepresented(policy_app_id)) {
    LOG4CXX_WARN(logger_,
                 "Application with id " << policy_app_id
                                        << " is not found within known apps.");
    return;
  }

  bool allowed_by_default = false;
  if (IsDefaultPolicy(policy_app_id)) {
    app_id_to_check = kDefaultID;
    allowed_by_default = true;
  } else if (IsPredataPolicy(policy_app_id) ||
             policy::kDeviceDisallowed == GetUserConsentForDevice(device_id)) {
    app_id_to_check = kPreDataConsentId;
    allowed_by_default = true;
  }

  FunctionalIdType group_types;
  if (!GetPermissionsForApp(device_id, app_id_to_check, group_types)) {
    LOG4CXX_WARN(logger_,
                 "Can't get user permissions for app " << policy_app_id);
    return;
  }

  // Functional groups w/o alias ("user_consent_prompt") considered as
  // automatically allowed and it could not be changed by user
  FunctionalGroupNames group_names;
  if (!GetFunctionalGroupNames(group_names)) {
    LOG4CXX_WARN(logger_, "Can't get functional group names");
    return;
  }

  // The "default" and "pre_DataConsent" are auto-allowed groups
  // So, check if application in the one of these mode.
  if (allowed_by_default) {
    LOG4CXX_INFO(logger_, "Get auto allowed groups");
    GroupType type =
        (kDefaultID == app_id_to_check ? kTypeDefault : kTypePreDataConsented);

    FillFunctionalGroupPermissions(
        group_types[type], group_names, kGroupAllowed, permissions);
  } else {
    // The code bellow allows to process application which
    // has specific permissions(not default and pre_DataConsent).

    // All groups for specific application
    FunctionalGroupIDs all_groups = group_types[kTypeGeneral];

    // Groups assigned by the user for specific application
    FunctionalGroupIDs allowed_groups = group_types[kTypeAllowed];

    // Groups disallowed by the user for specific application
    FunctionalGroupIDs common_disallowed = group_types[kTypeDisallowed];

    // Groups that allowed by default but can be changed by the user
    FunctionalGroupIDs preconsented_groups = group_types[kTypePreconsented];

    // Groups which has user consent promt but there is no any consnets now.
    FunctionalGroupIDs unconsented_groups = group_types[kTypeUnconsented];

    // Pull common groups from allowed and preconsented parts.
    FunctionalGroupIDs allowed_preconsented =
        Merge(allowed_groups, preconsented_groups);

    // Get all groups that we suppose are allowed.
    FunctionalGroupIDs all_allowed = Merge(allowed_preconsented, all_groups);

    // In case when same groups exists in disallowed and allowed tables,
    // disallowed one have priority over allowed. So we have to remove
    // all disallowed groups from allowed table.
    FunctionalGroupIDs common_allowed =
        ExcludeSame(all_allowed, common_disallowed);
    FunctionalGroupIDs consent_disallowed =
        ExcludeSame(unconsented_groups, preconsented_groups);

    // Disallowed groups are contain all directly disallowed,
    // plus unconsented minus preconsented.
    FunctionalGroupIDs all_disallowed =
        Merge(common_disallowed, consent_disallowed);

    // Fill result
    FillFunctionalGroupPermissions(
        consent_disallowed, group_names, kGroupUndefined, permissions);
    FillFunctionalGroupPermissions(
        common_allowed, group_names, kGroupAllowed, permissions);
    FillFunctionalGroupPermissions(
        all_disallowed, group_names, kGroupDisallowed, permissions);
  }
  return;
}

std::string& PolicyManagerImpl::GetCurrentDeviceId(
    const std::string& policy_app_id) const {
  LOG4CXX_INFO(logger_, "GetDeviceInfo");
  last_device_id_ = listener()->OnCurrentDeviceIdUpdateRequired(policy_app_id);
  return last_device_id_;
}

void PolicyManagerImpl::SetSystemLanguage(const std::string& language) {
  CACHE_MANAGER_CHECK_VOID();
  *pt_->policy_table.module_meta->language = language;
  Backup();
}

void PolicyManagerImpl::SetSystemInfo(const std::string& ccpu_version,
                                      const std::string& wers_country_code,
                                      const std::string& language) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  *pt_->policy_table.module_meta->ccpu_version = ccpu_version;
  *pt_->policy_table.module_meta->wers_country_code = wers_country_code;
  *pt_->policy_table.module_meta->language = language;
  // We have to set preloaded flag as false in policy table on any response
  // of GetSystemInfo (SDLAQ-CRS-2365)
  *pt_->policy_table.module_config.preloaded_pt = false;
  Backup();
}

void PolicyManagerImpl::OnSystemReady() {
  // Update policy table for the first time with system information
  if (!pt_ || (NULL == pt_->policy_table.module_meta->ccpu_version) ||
      (NULL == pt_->policy_table.module_meta->wers_country_code) ||
      (NULL == pt_->policy_table.module_meta->language)) {
    listener()->OnSystemInfoUpdateRequired();
  }
}

uint32_t PolicyManagerImpl::GetNotificationsNumber(
    const std::string& priority) const {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(0);
  typedef rpc::policy_table_interface_base::NumberOfNotificationsPerMinute NNPM;

  const NNPM& nnpm =
      pt_->policy_table.module_config.notifications_per_minute_by_priority;

  NNPM::const_iterator priority_iter = nnpm.find(priority);

  const uint32_t result =
      (nnpm.end() != priority_iter ? (*priority_iter).second : 0);
  return result;
}

bool PolicyManagerImpl::ExceededIgnitionCycles() {
  CACHE_MANAGER_CHECK(0);
  const uint8_t limit = std::max(
      static_cast<int>(
          pt_->policy_table.module_config.exchange_after_x_ignition_cycles),
      0);
  LOG4CXX_DEBUG(
      logger_,
      "IgnitionCyclesBeforeExchange limit:" << static_cast<int>(limit));
  uint8_t current = 0;

  const int last_exch = static_cast<int>(
      *pt_->policy_table.module_meta->ignition_cycles_since_last_exchange);
  current = std::max(last_exch, 0);
  LOG4CXX_DEBUG(
      logger_,
      "IgnitionCyclesBeforeExchange current:" << static_cast<int>(current));

  return 0 == std::max(limit - current, 0);
}

bool PolicyManagerImpl::IsPTValid(
    utils::SharedPtr<policy_table::Table> policy_table,
    policy_table::PolicyTableType type) const {
  policy_table->SetPolicyTableType(type);
  if (!policy_table->is_valid()) {
    LOG4CXX_ERROR(logger_, "Policy table is not valid.");
    rpc::ValidationReport report("policy_table");
    policy_table->ReportErrors(&report);
    LOG4CXX_DEBUG(logger_, "Errors: " << rpc::PrettyFormat(report));
    return false;
  }
  return true;
}

const PolicySettings& PolicyManagerImpl::get_settings() const {
  DCHECK(settings_);
  return *settings_;
}

void PolicyManagerImpl::UpdateAppConsentWithCCS(
    const std::string& device_id,
    const std::string& application_id,
    const GroupsNames& allowed_groups,
    const GroupsNames& disallowed_groups) {
  std::vector<FunctionalGroupPermission> current_permissions;
  GetUserConsentForApp(device_id, application_id, current_permissions);

  std::vector<FunctionalGroupPermission> ccs_groups_matches;
  ConsentsUpdater updater(
      allowed_groups, disallowed_groups, ccs_groups_matches);
  std::for_each(
      current_permissions.begin(), current_permissions.end(), updater);

  const std::string source = "GUI";

  PermissionConsent updated_user_permissions;
  updated_user_permissions.group_permissions = current_permissions;
  updated_user_permissions.device_id = device_id;
  updated_user_permissions.policy_app_id = application_id;
  updated_user_permissions.consent_source = source;

  // Need to check to which app to send notification since maybe app registered
  // from different device
  SetUserConsentForApp(updated_user_permissions);

  PermissionConsent updated_ccs_permissions;
  updated_ccs_permissions.group_permissions = ccs_groups_matches;
  updated_ccs_permissions.device_id = device_id;
  updated_ccs_permissions.policy_app_id = application_id;
  updated_user_permissions.consent_source = source;

  SetCCSConsentsForApp(updated_ccs_permissions);
}

void PolicyManagerImpl::NotifySystem(
    const PolicyManagerImpl::AppPoliciesValueType& app_policy) const {
  listener()->OnPendingPermissionChange(app_policy.first);
}

void PolicyManagerImpl::SendPermissionsToApp(
    const PolicyManagerImpl::AppPoliciesValueType& app_policy) {
  const std::string app_id = app_policy.first;

  const std::string device_id = GetCurrentDeviceId(app_id);
  if (device_id.empty()) {
    LOG4CXX_WARN(logger_,
                 "Couldn't find device info for application id: " << app_id);
    return;
  }
  std::vector<FunctionalGroupPermission> group_permissons;
  GetPermissionsForApp(device_id, app_id, group_permissons);

  Permissions notification_data;

  // Need to get rid of this call
  utils::SharedPtr<policy_table::Table> policy_table_snapshot =
      GenerateSnapshot();

  PrepareNotificationData(
      policy_table_snapshot->policy_table.functional_groupings,
      app_policy.second.groups,
      group_permissons,
      notification_data);

  LOG4CXX_INFO(logger_, "Send notification for application_id: " << app_id);
  listener()->OnPermissionsUpdated(
      app_id,
      notification_data,
      policy_table::EnumToJsonString(app_policy.second.default_hmi));
}

void PolicyManagerImpl::ProcessCCSStatusUpdate(
    const GroupsByCCSStatus& groups_by_status) {
  GroupsNames allowed_groups;
  GroupsNames disallowed_groups;
  CalculateGroupsConsentFromCCS(
      groups_by_status, allowed_groups, disallowed_groups);

  ApplicationsLinks known_links = GetKnownLinksFromPT();
  ApplicationsLinks registered_links = listener_->GetRegisteredLinks();

  ApplicationsLinks all_known;
  std::merge(known_links.begin(),
             known_links.end(),
             registered_links.begin(),
             registered_links.end(),
             std::inserter(all_known, all_known.begin()));

  ApplicationsLinks::const_iterator it_links = all_known.begin();
  for (; all_known.end() != it_links; ++it_links) {
    UpdateAppConsentWithCCS(
        it_links->first, it_links->second, allowed_groups, disallowed_groups);
  }
}

bool PolicyManagerImpl::SetCCSStatus(const CCSStatus& status) {
  LOG4CXX_AUTO_TRACE(logger_);
  if (status.empty()) {
    LOG4CXX_INFO(logger_, "No CCS status update.");
    return false;
  }

  ex_backup_ = utils::SharedPtr<PTRepresentation>::dynamic_pointer_cast<
      PTExtRepresentation>(backup_);

  if (!ex_backup_->SaveCCSStatus(status)) {
    return false;
  }

  GroupsByCCSStatus groups_by_status = GetGroupsWithSameEntities(status);
  ProcessCCSStatusUpdate(groups_by_status);

  return true;
}

CCSStatus PolicyManagerImpl::GetCCSStatus() {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock auto_lock(cache_lock_);
  ex_backup_ = utils::SharedPtr<PTRepresentation>::dynamic_pointer_cast<
      PTExtRepresentation>(backup_);
  return ex_backup_->GetCCSStatus();
}

bool PolicyManagerImpl::ApplyUpdate(const policy_table::Table& pt_update) {
  // Replace current data with updated
  sync_primitives::AutoLock auto_lock(cache_lock_);
  CACHE_MANAGER_CHECK(false);
  pt_->policy_table.functional_groupings =
      pt_update.policy_table.functional_groupings;

  policy_table::ApplicationPolicies::const_iterator iter =
      pt_update.policy_table.app_policies_section.apps.begin();
  policy_table::ApplicationPolicies::const_iterator iter_end =
      pt_update.policy_table.app_policies_section.apps.end();

  for (; iter != iter_end; ++iter) {
    if (iter->second.is_null()) {
      pt_->policy_table.app_policies_section.apps[iter->first] =
          policy_table::ApplicationParams();
      pt_->policy_table.app_policies_section.apps[iter->first].set_to_null();
      pt_->policy_table.app_policies_section.apps[iter->first].set_to_string(
          "");
    } else if (policy::kDefaultID == (iter->second).get_string()) {
      policy_table::ApplicationPolicies::const_iterator iter_default =
          pt_update.policy_table.app_policies_section.apps.find(kDefaultID);
      if (pt_update.policy_table.app_policies_section.apps.end() ==
          iter_default) {
        LOG4CXX_ERROR(logger_, "The default section was not found in PTU");
        continue;
      }
      ProcessUpdate(iter_default);
    } else {
      ProcessUpdate(iter);
    }
  }

  pt_->policy_table.module_config.SafeCopyFrom(
      pt_update.policy_table.module_config);

  pt_->policy_table.consumer_friendly_messages.assign_if_valid(
      pt_update.policy_table.consumer_friendly_messages);

  ResetCalculatedPermissions();
  Backup();

  if (*pt_->policy_table.module_config.preloaded_pt && pt_update.is_valid()) {
    *pt_->policy_table.module_config.preloaded_pt = false;
  }

  return true;
}

void PolicyManagerImpl::CalculateGroupsConsentFromCCS(
    const GroupsByCCSStatus& groups_by_ccs,
    GroupsNames& out_allowed_groups,
    GroupsNames& out_disallowed_groups) const {
  LOG4CXX_AUTO_TRACE(logger_);
  GroupSorter sorter(out_allowed_groups, out_disallowed_groups);
  std::for_each(groups_by_ccs.begin(), groups_by_ccs.end(), sorter);

  GroupsNames filtered_allowed_groups;
  std::set_difference(
      out_allowed_groups.begin(),
      out_allowed_groups.end(),
      out_disallowed_groups.begin(),
      out_disallowed_groups.end(),
      std::inserter(filtered_allowed_groups, filtered_allowed_groups.begin()));

  out_allowed_groups = filtered_allowed_groups;
}

bool PolicyManagerImpl::ExceededDays() {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(true);
  TimevalStruct current_time = date_time::DateTime::getCurrentTime();
  const int kSecondsInDay = 60 * 60 * 24;
  const int days = current_time.tv_sec / kSecondsInDay;

  DCHECK(std::numeric_limits<uint16_t>::max() >= days);

  if (std::numeric_limits<uint16_t>::max() <= days) {
    LOG4CXX_WARN(logger_, "The days since epoch exceeds maximum value.");
    return false;
  }
  const uint8_t limit = pt_->policy_table.module_config.exchange_after_x_days;
  LOG4CXX_DEBUG(logger_,
                "Exchange after: " << static_cast<int>(limit) << " days");

  const uint16_t days_after_epoch =
      (*pt_->policy_table.module_meta->pt_exchanged_x_days_after_epoch);
  LOG4CXX_DEBUG(logger_, "Epoch since last update: " << days_after_epoch);

  const uint16_t actual = std::max(
      static_cast<uint16_t>(static_cast<uint16_t>(days) - days_after_epoch),
      uint16_t(0));
  LOG4CXX_DEBUG(logger_, "The days since last update: " << actual);

  return 0 == std::max(limit - actual, 0);
}

void PolicyManagerImpl::KmsChanged(int kilometers) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  const int limit =
      std::max(static_cast<int>(
                   pt_->policy_table.module_config.exchange_after_x_kilometers),
               0);
  LOG4CXX_DEBUG(logger_, "KilometersBeforeExchange limit:" << limit);
  int last = 0;

  const int odo_val = static_cast<int>(
      *pt_->policy_table.module_meta->pt_exchanged_at_odometer_x);
  last = std::max(odo_val, 0);
  LOG4CXX_DEBUG(logger_, "KilometersBeforeExchange last:" << last);

  const int actual = std::max((kilometers - last), 0);
  LOG4CXX_DEBUG(logger_, "KilometersBeforeExchange actual:" << actual);

  if (0 == std::max(limit - actual, 0)) {
    LOG4CXX_INFO(logger_, "Enough kilometers passed to send for PT update.");
    update_status_manager_.ScheduleUpdate();
    StartPTExchange();
  }
}

void PolicyManagerImpl::IncrementIgnitionCycles() {
  CACHE_MANAGER_CHECK_VOID();
  const int ign_val = static_cast<int>(
      *pt_->policy_table.module_meta->ignition_cycles_since_last_exchange);
  (*pt_->policy_table.module_meta->ignition_cycles_since_last_exchange) =
      ign_val + 1;
  LOG4CXX_DEBUG(logger_, "IncrementIgnitionCycles ignitions:" << ign_val);
  Backup();
}

std::string PolicyManagerImpl::ForcePTExchange() {
  update_status_manager_.ScheduleUpdate();
  StartPTExchange();
  return update_status_manager_.StringifiedUpdateStatus();
}

std::string PolicyManagerImpl::GetPolicyTableStatus() const {
  return update_status_manager_.StringifiedUpdateStatus();
}

int PolicyManagerImpl::NextRetryTimeout() {
  sync_primitives::AutoLock auto_lock(retry_sequence_lock_);
  LOG4CXX_DEBUG(logger_, "Index: " << retry_sequence_index_);
  int next = 0;
  if (!retry_sequence_seconds_.empty() &&
      retry_sequence_index_ < retry_sequence_seconds_.size()) {
    next = retry_sequence_seconds_[retry_sequence_index_];
    ++retry_sequence_index_;
  }
  return next;
}

void PolicyManagerImpl::RefreshRetrySequence() {
  CACHE_MANAGER_CHECK_VOID();
  sync_primitives::AutoLock auto_lock(retry_sequence_lock_);
  retry_sequence_timeout_ =
      pt_->policy_table.module_config.timeout_after_x_seconds;
  retry_sequence_seconds_.clear();

  rpc::policy_table_interface_base::SecondsBetweenRetries::iterator iter =
      pt_->policy_table.module_config.seconds_between_retries.begin();
  rpc::policy_table_interface_base::SecondsBetweenRetries::iterator iter_end =
      pt_->policy_table.module_config.seconds_between_retries.end();
  const std::size_t size =
      pt_->policy_table.module_config.seconds_between_retries.size();
  retry_sequence_seconds_.reserve(size);
  for (; iter != iter_end; ++iter) {
    retry_sequence_seconds_.push_back(*iter);
  }
}

void PolicyManagerImpl::ResetRetrySequence() {
  sync_primitives::AutoLock auto_lock(retry_sequence_lock_);
  retry_sequence_index_ = 0;
  update_status_manager_.OnResetRetrySequence();
}

int PolicyManagerImpl::TimeoutExchange() {
  return retry_sequence_timeout_;
}

const std::vector<int> PolicyManagerImpl::RetrySequenceDelaysSeconds() {
  sync_primitives::AutoLock auto_lock(retry_sequence_lock_);
  return retry_sequence_seconds_;
}

void PolicyManagerImpl::OnExceededTimeout() {
  update_status_manager_.OnUpdateTimeoutOccurs();
}

void PolicyManagerImpl::OnUpdateStarted() {
  int update_timeout = TimeoutExchange();
  LOG4CXX_DEBUG(logger_,
                "Update timeout will be set to (sec): " << update_timeout);
  update_status_manager_.OnUpdateSentOut(update_timeout);
  SaveUpdateStatusRequired(true);
}

void PolicyManagerImpl::PTUpdatedAt(Counters counter, int value) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  switch (counter) {
    case KILOMETERS:
      *pt_->policy_table.module_meta->pt_exchanged_at_odometer_x = value;
      LOG4CXX_DEBUG(logger_,
                    "SetCountersPassedForSuccessfulUpdate km:" << value);
      break;
    case DAYS_AFTER_EPOCH:
      *pt_->policy_table.module_meta->pt_exchanged_x_days_after_epoch = value;
      LOG4CXX_DEBUG(
          logger_,
          "SetCountersPassedForSuccessfulUpdate days after epoch:" << value);
      break;
    default:
      LOG4CXX_ERROR(logger_,
                    "Unknown counter was requested to set: " << counter);
  }
  (*pt_->policy_table.module_meta->ignition_cycles_since_last_exchange) = 0;
  Backup();
}

void PolicyManagerImpl::Increment(usage_statistics::GlobalCounterId type) {
  LOG4CXX_INFO(logger_, "Increment without app id");
  sync_primitives::AutoLock lock(cache_lock_);
  CACHE_MANAGER_CHECK_VOID();
  switch (type) {
    case usage_statistics::IAP_BUFFER_FULL:
      ++(*pt_->policy_table.usage_and_error_counts->count_of_iap_buffer_full);
      break;
    case usage_statistics::SYNC_OUT_OF_MEMORY:
      ++(*pt_->policy_table.usage_and_error_counts->count_sync_out_of_memory);
      break;
    case usage_statistics::SYNC_REBOOTS:
      ++(*pt_->policy_table.usage_and_error_counts->count_of_sync_reboots);
      break;
    default:
      LOG4CXX_WARN(logger_, "Type global counter is unknown");
      return;
  }
  Backup();
}

void PolicyManagerImpl::Increment(const std::string& app_id,
                                  usage_statistics::AppCounterId type) {
  LOG4CXX_DEBUG(logger_, "Increment " << app_id << " AppCounter: " << type);
  sync_primitives::AutoLock lock(cache_lock_);
  CACHE_MANAGER_CHECK_VOID();
  switch (type) {
    case usage_statistics::USER_SELECTIONS:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_user_selections;
      break;
    case usage_statistics::REJECTIONS_SYNC_OUT_OF_MEMORY:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_rejections_sync_out_of_memory;
      break;
    case usage_statistics::REJECTIONS_NICKNAME_MISMATCH:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_rejections_nickname_mismatch;
      break;
    case usage_statistics::REJECTIONS_DUPLICATE_NAME:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_rejections_duplicate_name;
      break;
    case usage_statistics::REJECTED_RPC_CALLS:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_rejected_rpc_calls;
      break;
    case usage_statistics::RPCS_IN_HMI_NONE:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_rpcs_sent_in_hmi_none;
      break;
    case usage_statistics::REMOVALS_MISBEHAVED:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_removals_for_bad_behavior;
      break;
    case usage_statistics::RUN_ATTEMPTS_WHILE_REVOKED:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_run_attempts_while_revoked;
      break;
    case usage_statistics::COUNT_OF_TLS_ERRORS:
      ++(*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
            .count_of_tls_errors;
      break;
    default:
      LOG4CXX_WARN(logger_, "Type app counter is unknown");
      return;
  }
  Backup();
}

void PolicyManagerImpl::Set(const std::string& app_id,
                            usage_statistics::AppInfoId type,
                            const std::string& value) {
  LOG4CXX_INFO(logger_, "Set " << app_id);
  sync_primitives::AutoLock lock(cache_lock_);
  CACHE_MANAGER_CHECK_VOID();
  switch (type) {
    case usage_statistics::LANGUAGE_GUI:
      (*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
          .app_registration_language_gui = value;
      break;
    case usage_statistics::LANGUAGE_VUI:
      (*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
          .app_registration_language_vui = value;
      break;
    default:
      LOG4CXX_WARN(logger_, "Type app info is unknown");
      return;
  }
  Backup();
}

void PolicyManagerImpl::Add(const std::string& app_id,
                            usage_statistics::AppStopwatchId type,
                            int32_t timespan_seconds) {
  LOG4CXX_INFO(logger_, "Add " << app_id);
  sync_primitives::AutoLock lock(cache_lock_);
  CACHE_MANAGER_CHECK_VOID();
  const int minutes = ConvertSecondsToMinute(timespan_seconds);
  switch (type) {
    case usage_statistics::SECONDS_HMI_FULL:
      (*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
          .minutes_in_hmi_full += minutes;
      break;
    case usage_statistics::SECONDS_HMI_LIMITED:
      (*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
          .minutes_in_hmi_limited += minutes;
      break;
    case usage_statistics::SECONDS_HMI_BACKGROUND:
      (*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
          .minutes_in_hmi_background += minutes;
      break;
    case usage_statistics::SECONDS_HMI_NONE:
      (*pt_->policy_table.usage_and_error_counts->app_level)[app_id]
          .minutes_in_hmi_none += minutes;
      break;
    default:
      LOG4CXX_WARN(logger_, "Type app stopwatch is unknown");
      return;
  }
  Backup();
}

bool PolicyManagerImpl::IsApplicationRevoked(const std::string& app_id) const {
  CACHE_MANAGER_CHECK(false);
  bool is_revoked = false;
  if (IsApplicationRepresented(app_id)) {
    is_revoked = pt_->policy_table.app_policies_section.apps[app_id].is_null();
  }
  return is_revoked;
}

bool PolicyManagerImpl::IsConsentNeeded(const std::string& app_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  const std::string device_id = GetCurrentDeviceId(app_id);
  LOG4CXX_DEBUG(logger_, "Application id: " << app_id);
  if (kDeviceID != app_id && !IsApplicationRepresented(app_id)) {
    return 0;
  } else if (IsDefaultPolicy(app_id)) {
    return 0;
  } else if (IsPredataPolicy(app_id)) {
    return 0;
  }

  policy_table::FunctionalGroupings::const_iterator groups_iter_end =
      pt_->policy_table.functional_groupings.end();

  policy_table::ApplicationPoliciesSection& app_policies_section =
      pt_->policy_table.app_policies_section;

  policy_table::Strings::iterator app_groups;
  policy_table::Strings::iterator app_groups_end = app_groups;
  policy_table::Strings::iterator app_pre_groups;
  policy_table::Strings::iterator app_pre_groups_end = app_pre_groups;

  if (kDeviceID == app_id) {
    app_groups = app_policies_section.device.groups.begin();

    app_groups_end = app_policies_section.device.groups.end();

    app_pre_groups = app_policies_section.device.preconsented_groups->begin();

    app_pre_groups_end = app_policies_section.device.preconsented_groups->end();
  } else {
    app_groups = app_policies_section.apps[app_id].groups.begin();

    app_groups_end = app_policies_section.apps[app_id].groups.end();

    app_pre_groups =
        app_policies_section.apps[app_id].preconsented_groups->begin();

    app_pre_groups_end =
        app_policies_section.apps[app_id].preconsented_groups->end();
  }

  policy_table::Strings groups_to_be_consented;
  policy_table::FunctionalGroupings::iterator current_groups_iter;
  for (; app_groups != app_groups_end; ++app_groups) {
    current_groups_iter =
        pt_->policy_table.functional_groupings.find(*app_groups);

    if (groups_iter_end != current_groups_iter) {
      if (current_groups_iter->second.user_consent_prompt.is_initialized()) {
        // Check if groups which requires user consent prompt
        // not included in "preconsented_groups" section
        if (app_pre_groups_end ==
            std::find(app_pre_groups, app_pre_groups_end, *app_groups)) {
          groups_to_be_consented.push_back(*app_groups);
        }
      }
    }
  }

  if (groups_to_be_consented.empty()) {
    return 0;
  }

  // If there is no device record, all groups with consents should be consented
  if (pt_->policy_table.device_data->end() ==
      pt_->policy_table.device_data->find(device_id)) {
    return groups_to_be_consented.size();
  }

  policy_table::DeviceParams& params =
      (*pt_->policy_table.device_data)[device_id];

  policy_table::UserConsentRecords& ucr = *(params.user_consent_records);

  // If there is no application record, all groups with consents should be
  // consented
  if (ucr.end() == ucr.find(app_id)) {
    return groups_to_be_consented.size();
  }

  policy_table::ConsentRecords& cgr = ucr[app_id];

  policy_table::Strings::const_iterator to_consent_it =
      groups_to_be_consented.begin();

  int count = 0;
  for (; to_consent_it != groups_to_be_consented.end(); ++to_consent_it) {
    policy_table::ConsentGroups::const_iterator already_consented_iter =
        cgr.consent_groups->find(*to_consent_it);
    if (already_consented_iter == cgr.consent_groups->end()) {
      ++count;
    }
  }
  LOG4CXX_DEBUG(logger_, "There are: " << count << " unconsented groups.");
  return count != 0;
}

void PolicyManagerImpl::SetVINValue(const std::string& value) {
  cache_lock_.Acquire();
  CACHE_MANAGER_CHECK_VOID();
  *pt_->policy_table.module_meta->vin = value;
  cache_lock_.Release();
  Backup();
}

AppPermissions PolicyManagerImpl::GetAppPermissionsChanges(
    const std::string& policy_app_id) {
  PendingPermissions::iterator app_id_diff =
      app_permissions_diff_.find(policy_app_id);

  AppPermissions permissions(policy_app_id);

  if (app_permissions_diff_.end() != app_id_diff) {
    permissions = app_id_diff->second;
  } else {
    permissions.appPermissionsConsentNeeded = IsConsentNeeded(policy_app_id);
    permissions.appRevoked = IsApplicationRevoked(policy_app_id);
    GetPriority(permissions.application_id, &permissions.priority);
  }
  return permissions;
}

void PolicyManagerImpl::RemovePendingPermissionChanges(
    const std::string& app_id) {
  app_permissions_diff_.erase(app_id);
}

bool PolicyManagerImpl::CanAppKeepContext(const std::string& app_id) const {
  CACHE_MANAGER_CHECK(false);
  bool result = false;
  if (kDeviceID == app_id) {
    result = pt_->policy_table.app_policies_section.device.keep_context;
  } else if (IsApplicationRepresented(app_id)) {
    result = pt_->policy_table.app_policies_section.apps[app_id].keep_context;
  }
  return result;
}

bool PolicyManagerImpl::CanAppStealFocus(const std::string& app_id) const {
  CACHE_MANAGER_CHECK(false);
  bool result = false;
  if (kDeviceID == app_id) {
    result = pt_->policy_table.app_policies_section.device.steal_focus;
  } else if (IsApplicationRepresented(app_id)) {
    result = pt_->policy_table.app_policies_section.apps[app_id].steal_focus;
  }
  return result;
}

void PolicyManagerImpl::MarkUnpairedDevice(const std::string& device_id) {
  if (!SetUnpairedDevice(device_id)) {
    LOG4CXX_DEBUG(logger_, "Could not set unpaired flag for " << device_id);
    return;
  }
  SetUserConsentForDevice(device_id, false);
}

void PolicyManagerImpl::OnAppRegisteredOnMobile(
    const std::string& application_id) {
  StartPTExchange();
  SendNotificationOnPermissionsUpdated(application_id);
}

const MetaInfo PolicyManagerImpl::GetMetaInfo() const {
  LOG4CXX_AUTO_TRACE(logger_);
  MetaInfo meta_info;
  meta_info.ccpu_version = *pt_->policy_table.module_meta->ccpu_version;
  meta_info.wers_country_code =
      *pt_->policy_table.module_meta->wers_country_code;
  meta_info.language = *pt_->policy_table.module_meta->language;
  return meta_info;
}

std::string PolicyManagerImpl::RetrieveCertificate() const {
  LOG4CXX_AUTO_TRACE(logger_);
  return GetCertificate();
}

bool PolicyManagerImpl::HasCertificate() const {
  return !GetCertificate().empty();
}

void PolicyManagerImpl::SetDecryptedCertificate(
    const std::string& certificate) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  sync_primitives::AutoLock auto_lock(cache_lock_);
  *pt_->policy_table.module_config.certificate = certificate;
  Backup();
}

void PolicyManagerImpl::AddApplication(const std::string& application_id,
                                       const AppHmiTypes& hmi_types) {
  LOG4CXX_AUTO_TRACE(logger_);
  const std::string device_id = GetCurrentDeviceId(application_id);
  DeviceConsent device_consent = GetUserConsentForDevice(device_id);
  sync_primitives::AutoLock lock(apps_registration_lock_);

  if (IsNewApplication(application_id)) {
    AddNewApplication(application_id, device_consent);
    update_status_manager_.OnNewApplicationAdded();
  } else {
    PromoteExistedApplication(application_id, device_consent);
    if (helpers::in_range(hmi_types, policy_table::AHT_NAVIGATION) &&
        !HasCertificate()) {
      LOG4CXX_DEBUG(logger_, "Certificate does not exist, scheduling update.");
      update_status_manager_.ScheduleUpdate();
    }
  }
}

void PolicyManagerImpl::RemoveAppConsentForGroup(
    const std::string& app_id, const std::string& group_name) {
  CACHE_MANAGER_CHECK_VOID();
  policy_table::DeviceData::iterator device_iter =
      pt_->policy_table.device_data->begin();
  policy_table::DeviceData::iterator device_iter_end =
      pt_->policy_table.device_data->end();

  policy_table::UserConsentRecords::iterator ucr_iter;
  for (; device_iter != device_iter_end; ++device_iter) {
    ucr_iter = device_iter->second.user_consent_records->find(app_id);
    if (device_iter->second.user_consent_records->end() != ucr_iter) {
      ucr_iter->second.consent_groups->erase(group_name);
    }
  }
}

bool PolicyManagerImpl::IsPredataPolicy(const std::string& policy_app_id) {
  LOG4CXX_INFO(logger_, "IsPredataApp");
  // TODO(AOleynik): Maybe change for comparison with pre_DataConsent
  // permissions or check string value from get_string()
  policy_table::ApplicationParams& pre_data_app =
      pt_->policy_table.app_policies_section.apps[kPreDataConsentId];
  policy_table::ApplicationParams& specific_app =
      pt_->policy_table.app_policies_section.apps[policy_app_id];

  policy_table::Strings res;
  std::set_intersection(pre_data_app.groups.begin(),
                        pre_data_app.groups.end(),
                        specific_app.groups.begin(),
                        specific_app.groups.end(),
                        std::back_inserter(res));

  bool is_marked_as_predata =
      kPreDataConsentId ==
      pt_->policy_table.app_policies_section.apps[policy_app_id].get_string();

  return !res.empty() && is_marked_as_predata;
}

void PolicyManagerImpl::ProcessCCSStatusForApp(
    const std::string& application_id) {
  CCSStatus status = GetCCSStatus();
  GroupsByCCSStatus groups_by_status = GetGroupsWithSameEntities(status);

  GroupsNames allowed_groups;
  GroupsNames disallowed_groups;
  CalculateGroupsConsentFromCCS(
      groups_by_status, allowed_groups, disallowed_groups);

  const std::string device_id = GetCurrentDeviceId(application_id);
  UpdateAppConsentWithCCS(
      device_id, application_id, allowed_groups, disallowed_groups);
}

void PolicyManagerImpl::AddNewApplication(const std::string& application_id,
                                          DeviceConsent device_consent) {
  LOG4CXX_AUTO_TRACE(logger_);

  if (kDeviceHasNoConsent == device_consent ||
      kDeviceDisallowed == device_consent) {
    LOG4CXX_INFO(logger_,
                 "Setting "
                     << policy::kPreDataConsentId
                     << " permissions for application id: " << application_id);
    CACHE_MANAGER_CHECK_VOID();
    policy_table::ApplicationPolicies::const_iterator iter =
        pt_->policy_table.app_policies_section.apps.find(kPreDataConsentId);

    if (pt_->policy_table.app_policies_section.apps.end() == iter) {
      LOG4CXX_ERROR(logger_,
                    "Could not set " << kPreDataConsentId
                                     << " permissions for app "
                                     << application_id);
      return;
    }

    pt_->policy_table.app_policies_section.apps[application_id] =
        pt_->policy_table.app_policies_section.apps[kPreDataConsentId];

    pt_->policy_table.app_policies_section.apps[application_id].set_to_string(
        kPreDataConsentId);

    Backup();
  } else {
    LOG4CXX_INFO(logger_,
                 "Setting "
                     << policy::kDefaultID
                     << " permissions for application id: " << application_id);
    SetDefaultPolicy(application_id);
  }

  ProcessCCSStatusForApp(application_id);
}

void PolicyManagerImpl::PromoteExistedApplication(
    const std::string& application_id, DeviceConsent device_consent) {
  LOG4CXX_AUTO_TRACE(logger_);
  // If device consent changed to allowed during application being
  // disconnected, app permissions should be changed also
  if (kDeviceAllowed == device_consent && IsPredataPolicy(application_id)) {
    SetDefaultPolicy(application_id);
  }

  ProcessCCSStatusForApp(application_id);
}

bool PolicyManagerImpl::IsNewApplication(
    const std::string& application_id) const {
  return false == IsApplicationRepresented(application_id);
}

bool PolicyManagerImpl::ResetPT(const std::string& file_name) {
  LOG4CXX_AUTO_TRACE(logger_);
  ResetCalculatedPermissions();

  bool result = false;

  is_unpaired_.clear();
  if (!backup_->RefreshDB()) {
    LOG4CXX_ERROR(logger_, "Can't re-create policy database. Reset failed.");
  } else {
    sync_primitives::AutoLock lock(cache_lock_);
    pt_.reset(new policy_table::Table());
    result = LoadFromFile(file_name, *pt_);
    if (result) {
      Backup();
      *pt_->policy_table.module_config.preloaded_pt = true;
    }
  }

  if (result) {
    RefreshRetrySequence();
  }

  return result;
}

bool PolicyManagerImpl::CheckAppStorageFolder() const {
  LOG4CXX_AUTO_TRACE(logger_);
  const std::string app_storage_folder = get_settings().app_storage_folder();
  LOG4CXX_DEBUG(logger_, "AppStorageFolder " << app_storage_folder);
  if (!file_system::DirectoryExists(app_storage_folder)) {
    LOG4CXX_WARN(logger_,
                 "Storage directory doesn't exist " << app_storage_folder);
    return false;
  }
  if (!(file_system::IsWritingAllowed(app_storage_folder) &&
        file_system::IsReadingAllowed(app_storage_folder))) {
    LOG4CXX_WARN(logger_,
                 "Storage directory doesn't have read/write permissions "
                     << app_storage_folder);
    return false;
  }
  return true;
}

bool PolicyManagerImpl::InitPT(const std::string& file_name,
                               const PolicySettings* settings) {
  LOG4CXX_AUTO_TRACE(logger_);
  settings_ = settings;
  if (!CheckAppStorageFolder()) {
    LOG4CXX_ERROR(logger_, "Can not read/write into AppStorageFolder");
    return false;
  }

  InitResult init_result = backup_->Init(settings);
  ex_backup_ = utils::SharedPtr<PTRepresentation>::dynamic_pointer_cast<
      PTExtRepresentation>(backup_);

  bool result = true;
  switch (init_result) {
    case InitResult::EXISTS: {
      LOG4CXX_INFO(logger_, "Policy Table exists, was loaded correctly.");
      {
        sync_primitives::AutoLock lock(cache_lock_);
        pt_ = backup_->GenerateSnapshot();
        update_required = backup_->UpdateRequired();
        FillDeviceSpecificData();
      }
      if (result) {
        if (!backup_->IsDBVersionActual()) {
          if (!backup_->RefreshDB()) {
            return false;
          }
          backup_->UpdateDBVersion();
          Backup();
        }
        MergePreloadPT(file_name);
      }
    } break;
    case InitResult::SUCCESS: {
      LOG4CXX_INFO(logger_, "Policy Table was inited successfully");
      result = LoadFromFile(file_name, *pt_);
      utils::SharedPtr<policy_table::Table> snapshot = GenerateSnapshot();

      result &= snapshot->is_valid();
      LOG4CXX_DEBUG(logger_,
                    "Check if snapshot valid: " << std::boolalpha << result);

      if (result) {
        backup_->UpdateDBVersion();
        Backup();
        *pt_->policy_table.module_config.preloaded_pt = true;
      } else {
        rpc::ValidationReport report("policy_table");
        snapshot->ReportErrors(&report);
        ex_backup_->RemoveDB();
      }
    } break;
    default: {
      result = false;
      LOG4CXX_ERROR(logger_, "Failed to init policy table.");
    } break;
  }

  if (result) {
    RefreshRetrySequence();
    update_status_manager_.OnPolicyInit(update_required);
  }
  return result;
}

uint32_t PolicyManagerImpl::HeartBeatTimeout(const std::string& app_id) const {
  CACHE_MANAGER_CHECK(0);
  uint32_t result = 0;
  if (IsApplicationRepresented(app_id)) {
    if (pt_->policy_table.app_policies_section.apps[app_id]
            .heart_beat_timeout_ms.is_initialized()) {
      result = *(pt_->policy_table.app_policies_section.apps[app_id]
                     .heart_beat_timeout_ms);
    }
  }
  return result;
}

void PolicyManagerImpl::SaveUpdateStatusRequired(bool is_update_needed) {
  update_required = is_update_needed;
  Backup();
}

// FROM EX CACHE MANAGER /////////////////////////////////////////////////////

std::string PolicyManagerImpl::currentDateTime() {
  time_t now = time(0);
  struct tm tstruct;
  char buf[80];
  tstruct = *localtime(&now);
  // ISO_8601 format is expected, e.g. “2000-01-01T12:18:53Z”
  strftime(buf, sizeof(buf), "%Y-%m-%dT%XZ", &tstruct);
  return buf;
}

void PolicyManagerImpl::GetGroupNameByHashID(const int32_t group_id,
                                             std::string& group_name) {
  CACHE_MANAGER_CHECK_VOID();
  policy_table::FunctionalGroupings::const_iterator fg_iter =
      pt_->policy_table.functional_groupings.begin();
  policy_table::FunctionalGroupings::const_iterator fg_iter_end =
      pt_->policy_table.functional_groupings.end();

  for (; fg_iter != fg_iter_end; ++fg_iter) {
    const int32_t id = utils::Djb2HashFromString((*fg_iter).first);
    if (group_id == id) {
      group_name = (*fg_iter).first;
    }
  }
}

void PolicyManagerImpl::FillDeviceSpecificData() {
  DeviceIds unpaired_ids;
  ex_backup_->UnpairedDevicesList(&unpaired_ids);
  sync_primitives::AutoLock lock(unpaired_lock_);
  is_unpaired_.clear();
  for (DeviceIds::const_iterator ids_iter = unpaired_ids.begin();
       ids_iter != unpaired_ids.end();
       ++ids_iter) {
    is_unpaired_.insert(*ids_iter);
  }
}

long PolicyManagerImpl::ConvertSecondsToMinute(int seconds) {
  const float seconds_in_minute = 60.0;
  return std::round(seconds / seconds_in_minute);
}

void PolicyManagerImpl::CheckSnapshotInitialization() {
  CACHE_MANAGER_CHECK_VOID();
  if (!snapshot_) {
    LOG4CXX_ERROR(logger_, "Snapshot pointer is not initialized");
    return;
  }

  *(snapshot_->policy_table.module_config.preloaded_pt) = false;

  // SDL must not send certificate in snapshot
  snapshot_->policy_table.module_config.certificate =
      rpc::Optional<rpc::String<0, 65535> >();

  snapshot_->policy_table.consumer_friendly_messages->messages =
      rpc::Optional<policy_table::Messages>();

  rpc::Optional<policy_table::ModuleMeta>& module_meta =
      snapshot_->policy_table.module_meta;
  if (!module_meta->pt_exchanged_at_odometer_x->is_initialized()) {
    *(module_meta->pt_exchanged_at_odometer_x) = 0;
  }

  if (!module_meta->pt_exchanged_x_days_after_epoch->is_initialized()) {
    *(module_meta->pt_exchanged_x_days_after_epoch) = 0;
  }

  rpc::Optional<policy_table::UsageAndErrorCounts>& usage_and_error_counts =
      snapshot_->policy_table.usage_and_error_counts;
  if (!usage_and_error_counts->count_of_iap_buffer_full->is_initialized()) {
    *(usage_and_error_counts->count_of_iap_buffer_full) = 0;
  }

  if (!usage_and_error_counts->count_of_sync_reboots->is_initialized()) {
    *(usage_and_error_counts->count_of_sync_reboots) = 0;
  }

  if (!usage_and_error_counts->count_sync_out_of_memory->is_initialized()) {
    *(usage_and_error_counts->count_sync_out_of_memory) = 0;
  }

  if (usage_and_error_counts->app_level->is_initialized()) {
    policy_table::AppLevels::iterator it =
        usage_and_error_counts->app_level->begin();
    policy_table::AppLevels::const_iterator it_end =
        usage_and_error_counts->app_level->end();
    for (; it != it_end; ++it) {
      if (!(*it).second.minutes_in_hmi_full.is_initialized()) {
        (*it).second.minutes_in_hmi_full = 0;
      }

      if (!(*it).second.app_registration_language_gui.is_initialized()) {
        (*it).second.app_registration_language_gui = "unknown";
      }

      if (!(*it).second.app_registration_language_vui.is_initialized()) {
        (*it).second.app_registration_language_vui = "unknown";
      }

      if (!(*it).second.minutes_in_hmi_limited.is_initialized()) {
        (*it).second.minutes_in_hmi_limited = 0;
      }

      if (!(*it).second.minutes_in_hmi_background.is_initialized()) {
        (*it).second.minutes_in_hmi_background = 0;
      }

      if (!(*it).second.minutes_in_hmi_none.is_initialized()) {
        (*it).second.minutes_in_hmi_none = 0;
      }

      if (!(*it).second.count_of_user_selections.is_initialized()) {
        (*it).second.count_of_user_selections = 0;
      }

      if (!(*it)
               .second.count_of_rejections_sync_out_of_memory
               .is_initialized()) {
        (*it).second.count_of_rejections_sync_out_of_memory = 0;
      }

      if (!(*it)
               .second.count_of_rejections_nickname_mismatch.is_initialized()) {
        (*it).second.count_of_rejections_nickname_mismatch = 0;
      }

      if (!(*it).second.count_of_rejections_duplicate_name.is_initialized()) {
        (*it).second.count_of_rejections_duplicate_name = 0;
      }

      if (!(*it).second.count_of_rejected_rpc_calls.is_initialized()) {
        (*it).second.count_of_rejected_rpc_calls = 0;
      }

      if (!(*it).second.count_of_rpcs_sent_in_hmi_none.is_initialized()) {
        (*it).second.count_of_rpcs_sent_in_hmi_none = 0;
      }

      if (!(*it).second.count_of_removals_for_bad_behavior.is_initialized()) {
        (*it).second.count_of_removals_for_bad_behavior = 0;
      }

      if (!(*it).second.count_of_run_attempts_while_revoked.is_initialized()) {
        (*it).second.count_of_run_attempts_while_revoked = 0;
      }
    }
  }
}

void PolicyManagerImpl::PersistData() {
  LOG4CXX_AUTO_TRACE(logger_);
  if (backup_.valid()) {
    if (pt_.valid()) {
      cache_lock_.Acquire();
      policy_table::Table copy_pt(*pt_);
      cache_lock_.Release();

      backup_->Save(copy_pt);
      backup_->SaveUpdateRequired(update_required);

      policy_table::ApplicationPolicies::const_iterator app_policy_iter =
          copy_pt.policy_table.app_policies_section.apps.begin();
      policy_table::ApplicationPolicies::const_iterator app_policy_iter_end =
          copy_pt.policy_table.app_policies_section.apps.end();

      bool is_revoked = false;

      for (; app_policy_iter != app_policy_iter_end; ++app_policy_iter) {
        const std::string app_id = (*app_policy_iter).first;

        if (IsApplicationRepresented(app_id)) {
          is_revoked =
              copy_pt.policy_table.app_policies_section.apps[app_id].is_null();
        }

        const bool kIsDefaultPolicy =
            IsApplicationRepresented(app_id) &&
            policy::kDefaultID ==
                copy_pt.policy_table.app_policies_section.apps[app_id]
                    .get_string();

        // TODO(AOleynik): Remove this field from DB
        const bool kIsPredataPolicy =
            IsApplicationRepresented(app_id) &&
            policy::kPreDataConsentId ==
                copy_pt.policy_table.app_policies_section.apps[app_id]
                    .get_string();

        backup_->SaveApplicationCustomData(
            app_id, is_revoked, kIsDefaultPolicy, kIsPredataPolicy);
        is_revoked = false;
      }

      // In case of extended policy the meta info should be backuped as well.
      if (ex_backup_.valid()) {
        ex_backup_->SetMetaInfo(
            *(*copy_pt.policy_table.module_meta).ccpu_version,
            *(*copy_pt.policy_table.module_meta).wers_country_code,
            *(*copy_pt.policy_table.module_meta).language);
        ex_backup_->SetVINValue(*(*copy_pt.policy_table.module_meta).vin);

        // Save unpaired flag for devices
        policy_table::DeviceData::const_iterator it_device =
            copy_pt.policy_table.device_data->begin();
        policy_table::DeviceData::const_iterator it_end_device =
            copy_pt.policy_table.device_data->end();

#ifdef ENABLE_LOG
        policy_table::DeviceData& device_data =
            *copy_pt.policy_table.device_data;
        LOG4CXX_DEBUG(logger_, "Device_data size is: " << device_data.size());
#endif  // ENABLE_LOG
        for (; it_device != it_end_device; ++it_device) {
          if (is_unpaired_.end() != is_unpaired_.find(it_device->first)) {
            ex_backup_->SetUnpairedDevice(it_device->first, true);
          } else {
            ex_backup_->SetUnpairedDevice(it_device->first, false);
          }
        }
        LOG4CXX_DEBUG(logger_, "Device_data size is: " << device_data.size());
      }
      backup_->WriteDb();
    }
  }
}

void PolicyManagerImpl::ResetCalculatedPermissions() {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(calculated_permissions_lock_);
  calculated_permissions_.clear();
}

void PolicyManagerImpl::ResetCalculatedPermissionsForDevice(
    const std::string& device_id) {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(calculated_permissions_lock_);
  calculated_permissions_.erase(device_id);
}

void PolicyManagerImpl::AddCalculatedPermissions(
    const std::string& device_id,
    const std::string& policy_app_id,
    const Permissions& permissions) {
  LOG4CXX_DEBUG(logger_,
                "AddCalculatedPermissions for device: "
                    << device_id << " and app: " << policy_app_id);
  sync_primitives::AutoLock lock(calculated_permissions_lock_);
  calculated_permissions_[device_id][policy_app_id] = permissions;
}

bool PolicyManagerImpl::IsPermissionsCalculated(
    const std::string& device_id,
    const std::string& policy_app_id,
    Permissions& permission) {
  LOG4CXX_DEBUG(logger_,
                "IsPermissionsCalculated for device: "
                    << device_id << " and app: " << policy_app_id);
  sync_primitives::AutoLock lock(calculated_permissions_lock_);
  CalculatedPermissions::const_iterator it =
      calculated_permissions_.find(device_id);

  if (calculated_permissions_.end() == it) {
    return false;
  }

  AppCalculatedPermissions::const_iterator app_it =
      (*it).second.find(policy_app_id);
  if ((*it).second.end() == app_it) {
    return false;
  } else {
    permission = (*app_it).second;
    return true;
  }
  return false;
}

void PolicyManagerImpl::MergePreloadPT(const std::string& file_name) {
  LOG4CXX_AUTO_TRACE(logger_);
  policy_table::Table table;
  if (!LoadFromFile(file_name, table)) {
    LOG4CXX_DEBUG(logger_, "Unable to load preloaded PT.");
    return;
  }

  sync_primitives::AutoLock lock(cache_lock_);
  policy_table::PolicyTable& current = pt_->policy_table;
  policy_table::PolicyTable& new_table = table.policy_table;
  const std::string date_current = *current.module_config.preloaded_date;
  const std::string date_new = *new_table.module_config.preloaded_date;
  if (date_current != date_new) {
    MergeMC(new_table, current);
    MergeFG(new_table, current);
    MergeAP(new_table, current);
    MergeCFM(new_table, current);
    Backup();
  }
}

bool PolicyManagerImpl::GetPermissionsList(StringArray& perm_list) const {
  // Get device permission groups from app_policies section, which hadn't been
  // preconsented
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  policy_table::Strings groups =
      pt_->policy_table.app_policies_section.device.groups;
  policy_table::Strings preconsented_groups =
      *(pt_->policy_table.app_policies_section.device).preconsented_groups;
  std::for_each(groups.begin(),
                groups.end(),
                FunctionalGroupInserter(preconsented_groups, perm_list));
  return true;
}

DeviceConsent PolicyManagerImpl::GetCachedDeviceConsent(
    const std::string& device_id) const {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(cached_device_permissions_lock_);
  DeviceConsent result = kDeviceHasNoConsent;
  CACHE_MANAGER_CHECK(result);
  CachedDevicePermissions::const_iterator cached_dev_consent_iter;
  cached_dev_consent_iter = cached_device_permissions_.find(device_id);
  if (cached_dev_consent_iter != cached_device_permissions_.end()) {
    return cached_dev_consent_iter->second;
  }
  return result;
}

bool PolicyManagerImpl::HasDeviceSpecifiedConsent(const std::string& device_id,
                                                  const bool is_allowed) const {
  LOG4CXX_AUTO_TRACE(logger_);
  LOG4CXX_DEBUG(logger_, "Device :" << device_id);
  const DeviceConsent current_consent = GetDeviceConsent(device_id);
  const bool is_current_device_allowed =
      DeviceConsent::kDeviceAllowed == current_consent ? true : false;

  if (DeviceConsent::kDeviceHasNoConsent == current_consent ||
      is_current_device_allowed != is_allowed) {
    return false;
  }
  const std::string consent = is_allowed ? "allowed" : "disallowed";
  LOG4CXX_INFO(logger_,
               "DeviceGetDeviceGroupsFromPolicies is already " << consent
                                                               << ".");
  return true;
}

void PolicyManagerImpl::SaveDeviceConsentToCache(const std::string& device_id,
                                                 const bool is_allowed) {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(cached_device_permissions_lock_);
  CACHE_MANAGER_CHECK_VOID();
  DeviceConsent result = is_allowed ? kDeviceAllowed : kDeviceDisallowed;
  cached_device_permissions_[device_id] = result;
}

void PolicyManagerImpl::MergeMC(const policy_table::PolicyTable& new_pt,
                                policy_table::PolicyTable& pt) {
  LOG4CXX_AUTO_TRACE(logger_);
  policy_table::ModuleConfig copy(pt.module_config);

  pt.module_config = new_pt.module_config;
  pt.module_config.vehicle_make = copy.vehicle_make;
  pt.module_config.vehicle_year = copy.vehicle_year;
  pt.module_config.vehicle_model = copy.vehicle_model;
}

void PolicyManagerImpl::MergeFG(const policy_table::PolicyTable& new_pt,
                                policy_table::PolicyTable& pt) {
  LOG4CXX_AUTO_TRACE(logger_);
  policy_table::FunctionalGroupings::const_iterator it =
      new_pt.functional_groupings.begin();

  for (; it != new_pt.functional_groupings.end(); ++it) {
    LOG4CXX_DEBUG(logger_, "Merge functional group: " << it->first);
    pt.functional_groupings[it->first] = it->second;
  }
}

void PolicyManagerImpl::MergeAP(const policy_table::PolicyTable& new_pt,
                                policy_table::PolicyTable& pt) {
  LOG4CXX_AUTO_TRACE(logger_);
  pt.app_policies_section.device = const_cast<policy_table::PolicyTable&>(
                                       new_pt).app_policies_section.device;

  pt.app_policies_section.apps[kDefaultID] =
      const_cast<policy_table::PolicyTable&>(new_pt)
          .app_policies_section.apps[kDefaultID];

  pt.app_policies_section.apps[kPreDataConsentId] =
      const_cast<policy_table::PolicyTable&>(new_pt)
          .app_policies_section.apps[kPreDataConsentId];
}

void PolicyManagerImpl::MergeCFM(const policy_table::PolicyTable& new_pt,
                                 policy_table::PolicyTable& pt) {
  LOG4CXX_AUTO_TRACE(logger_);
  if (new_pt.consumer_friendly_messages.is_initialized()) {
    if (!pt.consumer_friendly_messages.is_initialized()) {
      pt.consumer_friendly_messages = new_pt.consumer_friendly_messages;
    } else {
      policy_table::Messages::const_iterator it =
          new_pt.consumer_friendly_messages->messages->begin();

      pt.consumer_friendly_messages->version =
          new_pt.consumer_friendly_messages->version;
      for (; it != new_pt.consumer_friendly_messages->messages->end(); ++it) {
        LOG4CXX_DEBUG(logger_, "Merge CFM: " << it->first);
        if (!(pt.consumer_friendly_messages->messages.is_initialized())) {
          LOG4CXX_DEBUG(logger_, "CFM not initialized.");
        }
        (*pt.consumer_friendly_messages->messages)[it->first] = it->second;
      }
    }
  }
}

void PolicyManagerImpl::InitBackupThread() {
  LOG4CXX_AUTO_TRACE(logger_);
  backuper_ = new BackgroundBackuper(this);
  backup_thread_ = threads::CreateThread("Backup thread", backuper_);
  backup_thread_->start();
}

using rpc::policy_table_interface_base::RequestTypes;
using rpc::policy_table_interface_base::RequestType;

void PolicyManagerImpl::ProcessUpdate(
    const policy_table::ApplicationPolicies::const_iterator
        initial_policy_iter) {
  using namespace policy;
  const RequestTypes& new_request_types =
      *(initial_policy_iter->second.RequestType);

  const std::string& app_id = initial_policy_iter->first;
  RequestTypes merged_pt_request_types;

  if (app_id == kDefaultID || app_id == kPreDataConsentId) {
    if (new_request_types.is_omitted()) {
      LOG4CXX_INFO(logger_,
                   "Application " << app_id
                                  << " has omitted RequestTypes."
                                     " Previous values will be kept.");
      return;
    }
    if (new_request_types.empty()) {
      if (new_request_types.is_cleaned_up()) {
        LOG4CXX_INFO(logger_,
                     "Application " << app_id
                                    << " has cleaned up all values."
                                       " Previous values will be kept.");
        return;
      }
      LOG4CXX_INFO(logger_,
                   "Application " << app_id
                                  << " has empty RequestTypes."
                                     " Any parameter will be allowed.");
    }
    merged_pt_request_types = new_request_types;
  } else {
    merged_pt_request_types = new_request_types;
  }
  pt_->policy_table.app_policies_section.apps[app_id] =
      initial_policy_iter->second;
  *(pt_->policy_table.app_policies_section.apps[app_id].RequestType) =
      merged_pt_request_types;
}

PolicyManagerImpl::BackgroundBackuper::BackgroundBackuper(
    PolicyManagerImpl* policy_manager_impl)
    : policy_manager_impl_(policy_manager_impl)
    , stop_flag_(false)
    , new_data_available_(false) {
  LOG4CXX_AUTO_TRACE(logger_);
}

PolicyManagerImpl::BackgroundBackuper::~BackgroundBackuper() {
  LOG4CXX_AUTO_TRACE(logger_);
}

void PolicyManagerImpl::BackgroundBackuper::threadMain() {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock lock(need_backup_lock_);
  while (!stop_flag_) {
    need_backup_lock_.Release();
    InternalBackup();
    need_backup_lock_.Acquire();
    if (new_data_available_ || stop_flag_) {
      continue;
    }
    LOG4CXX_DEBUG(logger_, "Wait for a next backup");
    backup_notifier_.Wait(need_backup_lock_);
  }
}

void PolicyManagerImpl::BackgroundBackuper::exitThreadMain() {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock auto_lock(need_backup_lock_);
  stop_flag_ = true;
  backup_notifier_.NotifyOne();
}

void PolicyManagerImpl::BackgroundBackuper::DoBackup() {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock auto_lock(need_backup_lock_);
  new_data_available_ = true;
  backup_notifier_.NotifyOne();
}

void PolicyManagerImpl::BackgroundBackuper::InternalBackup() {
  LOG4CXX_AUTO_TRACE(logger_);
  DCHECK(policy_manager_impl_);

  while (new_data_available_) {
    new_data_available_ = false;
    LOG4CXX_DEBUG(logger_, "DoBackup");
    policy_manager_impl_->PersistData();
  }
}

// FROM EX CACHE PUBLIC METHODS ////////////////////////////////////////////////

utils::SharedPtr<policy_table::Table> PolicyManagerImpl::GenerateSnapshot() {
  sync_primitives::AutoLock lock(cache_lock_);
  CACHE_MANAGER_CHECK(snapshot_);
  snapshot_ = utils::MakeShared<policy_table::Table>();
  snapshot_->policy_table = pt_->policy_table;

  snapshot_->SetPolicyTableType(policy_table::PT_SNAPSHOT);

  CheckSnapshotInitialization();
  return snapshot_;
}

bool PolicyManagerImpl::GetFunctionalGroupings(
    policy_table::FunctionalGroupings& groups) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  const policy_table::FunctionalGroupings& f_groupings =
      pt_->policy_table.functional_groupings;

  groups.insert(f_groupings.begin(), f_groupings.end());
  return true;
}

bool PolicyManagerImpl::IsApplicationRepresented(
    const std::string& app_id) const {
  CACHE_MANAGER_CHECK(false);
  if (kDeviceID == app_id) {
    return true;
  }
  policy_table::ApplicationPolicies::const_iterator iter =
      pt_->policy_table.app_policies_section.apps.find(app_id);
  return pt_->policy_table.app_policies_section.apps.end() != iter;
}

bool PolicyManagerImpl::IsDefaultPolicy(const std::string& app_id) {
  CACHE_MANAGER_CHECK(false);
  const bool result =
      IsApplicationRepresented(app_id) &&
      policy::kDefaultID ==
          pt_->policy_table.app_policies_section.apps[app_id].get_string();
  return result;
}

bool PolicyManagerImpl::SetDefaultPolicy(const std::string& app_id) {
  CACHE_MANAGER_CHECK(false);
  policy_table::ApplicationPolicies::const_iterator iter =
      pt_->policy_table.app_policies_section.apps.find(kDefaultID);
  if (pt_->policy_table.app_policies_section.apps.end() != iter) {
    pt_->policy_table.app_policies_section.apps[app_id] =
        pt_->policy_table.app_policies_section.apps[kDefaultID];

    if (IsApplicationRepresented(app_id)) {
      pt_->policy_table.app_policies_section.apps[app_id].set_to_string(
          kDefaultID);
    }
  }
  Backup();
  return true;
}

bool PolicyManagerImpl::GetUserPermissionsForDevice(
    const std::string& device_id,
    StringArray& consented_groups,
    StringArray& disallowed_groups) const {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  policy_table::DeviceData& device_data = *pt_->policy_table.device_data;
  if (device_data.end() == device_data.find(device_id)) {
    LOG4CXX_ERROR(logger_,
                  "Device with " << device_id << " was not found in PT");
    return false;
  }
  const policy_table::DeviceParams& params = device_data[device_id];
  const policy_table::UserConsentRecords& ucr = *(params.user_consent_records);
  policy_table::UserConsentRecords::const_iterator iter = ucr.begin();
  policy_table::UserConsentRecords::const_iterator iter_end = ucr.end();

  for (; iter != iter_end; ++iter) {
    policy_table::ConsentGroups::const_iterator con_iter;
    policy_table::ConsentGroups::const_iterator con_iter_end;

    con_iter = (*iter).second.consent_groups->begin();
    con_iter_end = (*iter).second.consent_groups->end();
    for (; con_iter != con_iter_end; ++con_iter) {
      if (true == (*con_iter).second) {
        consented_groups.push_back((*con_iter).first);
      } else {
        disallowed_groups.push_back((*con_iter).first);
      }
    }
  }
  return true;
}

bool PolicyManagerImpl::IsDeviceConsentCached(
    const std::string& device_id) const {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  sync_primitives::AutoLock lock(cached_device_permissions_lock_);
  CachedDevicePermissions::const_iterator cached_dev_consent_iter;
  cached_dev_consent_iter = cached_device_permissions_.find(device_id);
  return cached_dev_consent_iter != cached_device_permissions_.end();
}

DeviceConsent PolicyManagerImpl::GetDeviceConsent(
    const std::string& device_id) const {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(kDeviceHasNoConsent);
  if (IsDeviceConsentCached(device_id)) {
    return GetCachedDeviceConsent(device_id);
  }
  StringArray list_of_permissions;
  if (!GetPermissionsList(list_of_permissions)) {
    return kDeviceDisallowed;
  }

  // Check device permission groups for user consent in device_data
  // section
  if (list_of_permissions.empty()) {
    return kDeviceAllowed;
  }
  StringArray consented_groups;
  StringArray disallowed_groups;
  if (!GetUserPermissionsForDevice(
          device_id, consented_groups, disallowed_groups)) {
    return kDeviceDisallowed;
  }

  if (consented_groups.empty() && disallowed_groups.empty()) {
    return kDeviceHasNoConsent;
  }

  std::sort(list_of_permissions.begin(), list_of_permissions.end());
  std::sort(consented_groups.begin(), consented_groups.end());

  StringArray to_be_consented_by_user;
  std::set_difference(list_of_permissions.begin(),
                      list_of_permissions.end(),
                      consented_groups.begin(),
                      consented_groups.end(),
                      std::back_inserter(to_be_consented_by_user));
  if (to_be_consented_by_user.empty()) {
    return kDeviceAllowed;
  }
  return kDeviceDisallowed;
}

bool PolicyManagerImpl::GetPermissionsForApp(const std::string& device_id,
                                             const std::string& app_id,
                                             FunctionalIdType& group_types) {
  LOG4CXX_AUTO_TRACE(logger_);
  GetAllAppGroups(app_id, group_types[kTypeGeneral]);
  GetAllAppGroups(kDefaultID, group_types[kTypeDefault]);
  GetAllAppGroups(kPreDataConsentId, group_types[kTypePreDataConsented]);
  GetPreConsentedGroups(app_id, group_types[kTypePreconsented]);

  GetConsentedGroups(device_id,
                     app_id,
                     group_types[kTypeAllowed],
                     group_types[kTypeDisallowed]);

  GetUnconsentedGroups(device_id, app_id, group_types[kTypeUnconsented]);

  GetAllAppGroups(kDeviceID, group_types[kTypeDevice]);
  return true;
}

bool PolicyManagerImpl::SetUserPermissionsForDevice(
    const std::string& device_id,
    const StringArray& consented_groups,
    const StringArray& disallowed_groups) {
  LOG4CXX_AUTO_TRACE(logger_);
  sync_primitives::AutoLock auto_lock(cache_lock_);
  CACHE_MANAGER_CHECK(false);
  policy_table::DeviceParams& params =
      (*pt_->policy_table.device_data)[device_id];
  policy_table::UserConsentRecords& ucr = *(params.user_consent_records);

  StringArray::const_iterator consent_iter_end = consented_groups.end();
  StringArray::const_iterator consent_iter = consented_groups.begin();
  StringArray::const_iterator un_consent_iter_end = disallowed_groups.end();
  StringArray::const_iterator un_consent_iter = disallowed_groups.begin();

  for (; consent_iter != consent_iter_end; ++consent_iter) {
    (*ucr[kDeviceID].consent_groups)[*consent_iter] = true;
  }

  for (; un_consent_iter != un_consent_iter_end; ++un_consent_iter) {
    (*ucr[kDeviceID].consent_groups)[*un_consent_iter] = false;
  }

  policy_table::UserConsentRecords::iterator ucr_iter = ucr.begin();
  policy_table::UserConsentRecords::iterator ucr_iter_end = ucr.end();
  // TODO(AGaliuzov): Get this info from external data
  for (; ucr_iter != ucr_iter_end; ++ucr_iter) {
    *ucr_iter->second.input = policy_table::Input::I_GUI;
    *ucr_iter->second.time_stamp = currentDateTime();
  }
  Backup();
  return true;
}

bool PolicyManagerImpl::GetFunctionalGroupNames(FunctionalGroupNames& names) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(false);
  rpc::policy_table_interface_base::FunctionalGroupings::iterator iter =
      pt_->policy_table.functional_groupings.begin();
  rpc::policy_table_interface_base::FunctionalGroupings::iterator iter_end =
      pt_->policy_table.functional_groupings.end();

  for (; iter != iter_end; ++iter) {
    const int32_t id = utils::Djb2HashFromString((*iter).first);
    std::pair<std::string, std::string> value =
        std::make_pair(*(*iter).second.user_consent_prompt, (*iter).first);

    names.insert(
        std::pair<uint32_t, std::pair<std::string, std::string> >(id, value));
  }
  return true;
}

void PolicyManagerImpl::GetAllAppGroups(const std::string& app_id,
                                        FunctionalGroupIDs& all_group_ids) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  if (kDeviceID == app_id) {
    policy_table::DevicePolicy& device =
        pt_->policy_table.app_policies_section.device;

    policy_table::Strings::const_iterator iter = device.groups.begin();
    policy_table::Strings::const_iterator iter_end = device.groups.end();

    for (; iter != iter_end; ++iter) {
      const uint32_t group_id =
          static_cast<uint32_t>((utils::Djb2HashFromString(*iter)));
      all_group_ids.push_back(group_id);
    }

    return;
  }

  policy_table::ApplicationPolicies::const_iterator app_params_iter =
      pt_->policy_table.app_policies_section.apps.find(app_id);

  if (pt_->policy_table.app_policies_section.apps.end() != app_params_iter) {
    policy_table::Strings::const_iterator iter =
        (*app_params_iter).second.groups.begin();
    policy_table::Strings::const_iterator iter_end =
        (*app_params_iter).second.groups.end();

    for (; iter != iter_end; ++iter) {
      const uint32_t group_id =
          static_cast<uint32_t>((utils::Djb2HashFromString(*iter)));
      all_group_ids.push_back(group_id);
    }
  }
}

void PolicyManagerImpl::GetPreConsentedGroups(
    const std::string& app_id, FunctionalGroupIDs& preconsented_groups) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  if (kDeviceID == app_id) {
    policy_table::DevicePolicy& device =
        pt_->policy_table.app_policies_section.device;

    policy_table::Strings::const_iterator iter =
        device.preconsented_groups->begin();
    policy_table::Strings::const_iterator iter_end =
        device.preconsented_groups->end();

    for (; iter != iter_end; ++iter) {
      const uint32_t group_id =
          static_cast<uint32_t>((utils::Djb2HashFromString(*iter)));
      preconsented_groups.push_back(group_id);
    }

    return;
  }

  policy_table::ApplicationPolicies::const_iterator app_param_iter =
      pt_->policy_table.app_policies_section.apps.find(app_id);
  if (pt_->policy_table.app_policies_section.apps.end() != app_param_iter) {
    policy_table::Strings::const_iterator iter =
        (*app_param_iter).second.preconsented_groups->begin();
    policy_table::Strings::const_iterator iter_end =
        (*app_param_iter).second.preconsented_groups->end();
    for (; iter != iter_end; ++iter) {
      const int32_t group_id = utils::Djb2HashFromString(*iter);

      preconsented_groups.push_back(group_id);
    }
  }
}

void PolicyManagerImpl::GetConsentedGroups(
    const std::string& device_id,
    const std::string& app_id,
    FunctionalGroupIDs& allowed_groups,
    FunctionalGroupIDs& disallowed_groups) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  policy_table::DeviceData::iterator dev_params_iter =
      pt_->policy_table.device_data->find(device_id);

  if (pt_->policy_table.device_data->end() != dev_params_iter) {
    const policy_table::DeviceParams& dev_par = (*dev_params_iter).second;

    policy_table::UserConsentRecords::const_iterator iter =
        dev_par.user_consent_records->find(app_id);

    if (dev_par.user_consent_records->end() != iter) {
      policy_table::ConsentGroups::const_iterator consent_iter =
          (*iter).second.consent_groups->begin();
      policy_table::ConsentGroups::const_iterator consent_iter_end =
          (*iter).second.consent_groups->end();

      for (; consent_iter != consent_iter_end; ++consent_iter) {
        const int32_t group_id =
            utils::Djb2HashFromString((*consent_iter).first);

        if (true == (*consent_iter).second) {
          allowed_groups.push_back(group_id);
        } else {
          disallowed_groups.push_back(group_id);
        }
      }
    }
  }
}

void PolicyManagerImpl::GetUnconsentedGroups(
    const std::string& device_id,
    const std::string& policy_app_id,
    FunctionalGroupIDs& unconsented_groups) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();

  if (!IsApplicationRepresented(policy_app_id)) {
    LOG4CXX_WARN(logger_,
                 "The application with app_id: " << policy_app_id
                                                 << " is not reresented");
    return;
  }

  policy_table::Strings::iterator iter_groups;
  policy_table::Strings::iterator iter_groups_end;
  if (kDeviceID == policy_app_id) {
    iter_groups = pt_->policy_table.app_policies_section.device.groups.begin();
    iter_groups_end =
        pt_->policy_table.app_policies_section.device.groups.end();
  } else {
    iter_groups = pt_->policy_table.app_policies_section.apps[policy_app_id]
                      .groups.begin();
    iter_groups_end =
        pt_->policy_table.app_policies_section.apps[policy_app_id].groups.end();
  }

  for (; iter_groups != iter_groups_end; ++iter_groups) {
    // Try to find app-specific group in common groups list;
    policy_table::FunctionalGroupings::const_iterator func_groups =
        pt_->policy_table.functional_groupings.find(*iter_groups);
    if (pt_->policy_table.functional_groupings.end() != func_groups) {
      // Check if groups have user consents field.
      if (func_groups->second.user_consent_prompt.is_initialized()) {
        // Try to find certain group among already consented groups.
        policy_table::DeviceData::const_iterator device_iter =
            pt_->policy_table.device_data->find(device_id);
        if (pt_->policy_table.device_data->end() != device_iter) {
          policy_table::UserConsentRecords::const_iterator ucr_iter =
              device_iter->second.user_consent_records->find(policy_app_id);
          if (device_iter->second.user_consent_records->end() != ucr_iter) {
            if ((*ucr_iter).second.consent_groups->end() ==
                (*ucr_iter).second.consent_groups->find(*iter_groups)) {
              unconsented_groups.push_back(
                  utils::Djb2HashFromString(*iter_groups));
            }
          } else {
            unconsented_groups.push_back(
                utils::Djb2HashFromString(*iter_groups));
          }
        }
      }
    }
  }
}

bool PolicyManagerImpl::SetUnpairedDevice(const std::string& device_id,
                                          bool unpaired) {
  const bool result = pt_->policy_table.device_data->end() !=
                      pt_->policy_table.device_data->find(device_id);
  if (!result) {
    LOG4CXX_DEBUG(logger_,
                  "Couldn't set unpaired flag for device id "
                      << device_id << " , since it wasn't found.");
    return false;
  }

  sync_primitives::AutoLock lock(unpaired_lock_);
  if (unpaired) {
    is_unpaired_.insert(device_id);
    LOG4CXX_DEBUG(logger_, "Unpaired flag was set for device id " << device_id);
  } else {
    is_unpaired_.erase(device_id);
    LOG4CXX_DEBUG(logger_,
                  "Unpaired flag was removed for device id " << device_id);
  }
  return result;
}

bool PolicyManagerImpl::LoadFromFile(const std::string& file_name,
                                     policy_table::Table& table) {
  LOG4CXX_AUTO_TRACE(logger_);
  LOG4CXX_DEBUG(logger_, "Loading policy table from file " << file_name);
  BinaryMessage json_string;
  if (!file_system::ReadBinaryFile(file_name, json_string)) {
    LOG4CXX_FATAL(logger_, "Failed to read policy table source file.");
    return false;
  }

  Json::Value value;
  Json::Reader reader(Json::Features::strictMode());
  std::string json(json_string.begin(), json_string.end());
  if (!reader.parse(json.c_str(), value)) {
    LOG4CXX_FATAL(
        logger_,
        "Preloaded PT is corrupted: " << reader.getFormattedErrorMessages());
    return false;
  }

  LOG4CXX_DEBUG(logger_,
                "Start verification of policy table loaded from file.");

  table = policy_table::Table(&value);

#ifdef ENABLE_LOG
  Json::StyledWriter s_writer;
  LOG4CXX_DEBUG(
      logger_,
      "Policy table content loaded:" << s_writer.write(table.ToJsonValue()));
#endif  // ENABLE_LOG

  if (!table.is_valid()) {
    rpc::ValidationReport report("policy_table");
    table.ReportErrors(&report);
    LOG4CXX_FATAL(logger_,
                  "Parsed table is not valid " << rpc::PrettyFormat(report));
    return false;
  }
  return true;
}

void PolicyManagerImpl::Backup() {
  sync_primitives::AutoLock lock(backuper_locker_);
  DCHECK(backuper_);
  backuper_->DoBackup();
}

std::string PolicyManagerImpl::GetCertificate() const {
  CACHE_MANAGER_CHECK(std::string(""));
  if (pt_->policy_table.module_config.certificate.is_initialized()) {
    return *pt_->policy_table.module_config.certificate;
  }
  return std::string("");
}

GroupsByCCSStatus PolicyManagerImpl::GetGroupsWithSameEntities(
    const CCSStatus& status) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(policy::GroupsByCCSStatus());
  sync_primitives::AutoLock auto_lock(cache_lock_);
  GroupsByCCSStatus groups_by_ccs;

  GroupByCCSItemFinder groups_by_ccs_finder(
      pt_->policy_table.functional_groupings, groups_by_ccs);
  std::for_each(status.begin(), status.end(), groups_by_ccs_finder);

  return groups_by_ccs;
}

ApplicationsLinks PolicyManagerImpl::GetKnownLinksFromPT() {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK(ApplicationsLinks());
  ApplicationsLinks links;
  sync_primitives::AutoLock auto_lock(cache_lock_);

  LinkCollector collector(links);
  std::for_each(pt_->policy_table.device_data->begin(),
                pt_->policy_table.device_data->end(),
                collector);

  return links;
}

void PolicyManagerImpl::SetCCSConsentsForApp(
    const PermissionConsent& permissions) {
  LOG4CXX_AUTO_TRACE(logger_);
  CACHE_MANAGER_CHECK_VOID();
  sync_primitives::AutoLock auto_lock(cache_lock_);
  policy_table::ConsentGroups& ccs_groups =
      *(*(*pt_->policy_table.device_data)[permissions.device_id]
             .user_consent_records)[permissions.policy_app_id]
           .ccs_consent_groups;

  ccs_groups.clear();

  CCSConsentGroupAppender appender;
  std::transform(permissions.group_permissions.begin(),
                 permissions.group_permissions.end(),
                 std::inserter(ccs_groups, ccs_groups.begin()),
                 appender);

  Backup();
}

}  //  namespace policy
