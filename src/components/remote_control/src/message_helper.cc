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

#include <string>
#include "remote_control/message_helper.h"
#include "remote_control/rc_module_constants.h"
#include "utils/make_shared.h"

namespace remote_control {
using functional_modules::MobileFunctionID;
namespace {
std::map<MobileFunctionID, std::string> GenerateAPINames() {
  std::map<MobileFunctionID, std::string> result;
  result.insert(std::make_pair<MobileFunctionID, std::string>(
      MobileFunctionID::BUTTON_PRESS, "ButtonPress"));
  result.insert(std::make_pair<MobileFunctionID, std::string>(
      MobileFunctionID::GET_INTERIOR_VEHICLE_DATA, "GetInteriorVehicleData"));
  result.insert(std::make_pair<MobileFunctionID, std::string>(
      MobileFunctionID::SET_INTERIOR_VEHICLE_DATA, "SetInteriorVehicleData"));
  result.insert(std::make_pair<MobileFunctionID, std::string>(
      MobileFunctionID::ON_INTERIOR_VEHICLE_DATA, "OnInteriorVehicleData"));
  return result;
}
}

uint32_t MessageHelper::next_correlation_id_ = 1;
const std::map<MobileFunctionID, std::string> MessageHelper::kMobileAPINames =
    GenerateAPINames();

uint32_t MessageHelper::GetNextRCCorrelationID() {
  return next_correlation_id_++;
}

const std::string MessageHelper::GetMobileAPIName(MobileFunctionID func_id) {
  std::map<MobileFunctionID, std::string>::const_iterator it =
      kMobileAPINames.find(func_id);
  if (kMobileAPINames.end() != it) {
    return it->second;
  } else {
    return "";
  }
}

std::string MessageHelper::ValueToString(const Json::Value& value) {
  Json::FastWriter writer;

  return writer.write(value);
}

Json::Value MessageHelper::StringToValue(const std::string& string) {
  Json::Reader reader;

  Json::Value json;

  if (reader.parse(string, json)) {
    return json;
  }

  return Json::Value(Json::ValueType::nullValue);
}

bool IsMember(const Json::Value& value, const std::string& key) {
  if (!value.isObject()) {
    return false;
  }

  return value.isMember(key);
}

// TODO(KKolodiy): after creating commands for notification from HMI
// this validate methods may move to commands
bool MessageHelper::ValidateDeviceInfo(const Json::Value& value) {
  return value.isObject() && value.isMember(json_keys::kId) &&
         value.isMember(message_params::kName) &&
         value[message_params::kName].isString();
}

application_manager::MessagePtr MessageHelper::CreateHmiRequest(
    const char* function_id,
    const uint32_t hmi_app_id,
    const Json::Value& message_params,
    RemotePluginInterface& rc_module) {
  using namespace json_keys;
  Json::Value msg;

  msg[json_keys::kId] = rc_module.service()->GetNextCorrelationID();

  msg[kJsonrpc] = "2.0";
  msg[kMethod] = function_id;
  if (!message_params.isNull()) {
    msg[kParams] = message_params;
  }

  msg[kParams][json_keys::kAppId] = hmi_app_id;

  Json::FastWriter writer;
  application_manager::MessagePtr message_to_send =
      utils::MakeShared<application_manager::Message>(
          application_manager::Message(
              protocol_handler::MessagePriority::kDefault));
  message_to_send->set_protocol_version(
      application_manager::ProtocolVersion::kHMI);
  message_to_send->set_correlation_id(msg[json_keys::kId].asInt());
  message_to_send->set_function_name(msg[kMethod].asString());
  std::string json_msg = writer.write(msg);
  message_to_send->set_json_message(json_msg);
  message_to_send->set_message_type(application_manager::MessageType::kRequest);

  return message_to_send;
}

}  // namespace remote_control
