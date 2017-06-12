/*
 * Copyright (c) 2016, Ford Motor Company
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the
 * distribution.
 *
 * Neither the name of the Ford Motor Company nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "application_manager/system_time/system_time_handler_impl.h"

#include <algorithm>

#include "application_manager/message_helper.h"
#include "application_manager/smart_object_keys.h"
#include "interfaces/HMI_API.h"
#include "utils/logger.h"

namespace application_manager {

SystemTimeHandlerImpl::SystemTimeHandlerImpl(
    ApplicationManager& application_manager)
    : event_engine::EventObserver(application_manager.event_dispatcher())
    , is_utc_ready_(false)
    , schedule_request_(false)
    , system_time_listener_(NULL)
    , app_manager_(application_manager) {
  LOG4CXX_AUTO_TRACE(logger_);
}

SystemTimeHandlerImpl::~SystemTimeHandlerImpl() {
  LOG4CXX_AUTO_TRACE(logger_);
}

void SystemTimeHandlerImpl::DoSystemTimeQuery() {
  LOG4CXX_AUTO_TRACE(logger_);
  SendTimeRequest();
}

void SystemTimeHandlerImpl::DoSubscribe(utils::SystemTimeListener* listener) {
  sync_primitives::AutoLock lock(system_time_listener_lock_);
  system_time_listener_ = listener;
}

void SystemTimeHandlerImpl::DoUnsubscribe(utils::SystemTimeListener* listener) {
  sync_primitives::AutoLock lock(system_time_listener_lock_);
  system_time_listener_ = NULL;
}

time_t SystemTimeHandlerImpl::FetchSystemTime() {
  return last_time_;
}

void SystemTimeHandlerImpl::SendTimeRequest() {
  // Here can be request to some external system time source
  // At the moment no external source is used for open source, so use usual
  // system time

  application_manager::event_engine::Event dummy_event(
      hmi_apis::FunctionID::INVALID_ENUM);

  OnSystemTimeResponse(dummy_event);
}

void SystemTimeHandlerImpl::on_event(
    const application_manager::event_engine::Event& event) {}

void SystemTimeHandlerImpl::OnSystemTimeReady() {}

void SystemTimeHandlerImpl::OnSystemTimeResponse(
    const application_manager::event_engine::Event& event) {
  const smart_objects::SmartObject& message = event.smart_object();
  // At the moment just dummy variable
  UNUSED(message);

  // Currently use just usual time w/o any external source
  time(&last_time_);

  sync_primitives::AutoLock lock(system_time_listener_lock_);
  if (system_time_listener_) {
    system_time_listener_->OnSystemTimeArrived(last_time_);
  }
}

}  // namespace application_manager
