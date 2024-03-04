#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>


#include "NasEnum.h"

namespace nas {

/**************************************
 * NasUtils************************************************/

class NasUtils {

public:
  static bool getBit(const uint8_t &octet, uint8_t pos) {
    return (octet >> pos) & 0x1;
  }
  static void setBit(uint8_t &octet, uint8_t pos) { octet |= (1 << (pos - 1)); }

  static void resetBit(uint8_t &octet, uint8_t pos) {
    octet &= ~(1 << (pos - 1));
  }

  static std::vector<uint8_t> HexStringToVector(const std::string &hex) {
    if (hex.length() % 2 != 0)
      throw std::runtime_error("hex string has an odd length");

    for (char c : hex) {
      if (c >= '0' && c <= '9')
        continue;
      if (c >= 'a' && c <= 'f')
        continue;
      if (c >= 'A' && c <= 'F')
        continue;
      throw std::runtime_error("hex string contains invalid characters");
    }

    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
      std::string byteString = hex.substr(i, 2);
      char byte = (char)strtol(byteString.c_str(), nullptr, 16);
      bytes.emplace_back(byte);
    }
    return bytes;
  }

  static std::string UtfStringToHexString(const std::string &utfStr) {

    std::stringstream ss;
    if (utfStr.size() <= 0)
      return ss.str();

    ss << std::hex << std::setfill('0');
    uint32_t i = 0;
    for (auto &ch : utfStr) {
      ss << std::hex << std::setw(2) << static_cast<int>(ch) << " ";
      if ((i + 1) % 8 == 0)
        ss << " ";
      if ((i + 1) % 16 == 0)
        ss << "\n";
      ++i;
    }
    return ss.str();
  }

  static std::string U8VectorToString(std::vector<uint8_t> &buffer) {
    std::stringstream ss;
    if (buffer.size() <= 0)
      return ss.str();

    for (auto &ch : buffer) {
      ss << static_cast<char>(ch);
    }
    return ss.str();
  }
  static std::string Enum2String(RegistrationType v) {
    std::string str;
    switch (v) {
    case RegistrationType::INITIAL_REGISTRATION:
      str = "Initial Registration";
    case RegistrationType::MOBILITY_REGISTRATION_UPDATING:
      str = "Mobility Registration";
    case RegistrationType::PERIODIC_REGISTRATION_UPDATING:
      str = "Periodic Registration";
    case RegistrationType::EMERGENCY_REGISTRATION:
      str = "Emergency Registration";
    default:
      str = "?";
    }
    return str;
  }
  static std::string Enum2String(ExtendedProtocolDiscriminator v) {
    std::string str;
    switch (v) {
    case ExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES:
      str = "MOBILITY_MANAGEMENT_MESSAGES";
      break;
    case ExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES:
      str = "SESSION_MANAGEMENT_MESSAGES";
      break;
    default:
      str = "?";
      break;
    }
    return str;
  }
  static std::string Enum2String(MessageType msgtype) {
    std::string str;
    switch (msgtype) {
    case MessageType::REGISTRATION_REQUEST:
      str = "REGISTRATION_REQUEST";
      break;
    case MessageType::REGISTRATION_ACCEPT:
      str = "REGISTRATION_ACCEPT";
      break;
    case MessageType::REGISTRATION_COMPLETE:
      str = "REGISTRATION_COMPLETE";
      break;
    case MessageType::REGISTRATION_REJECT:
      str = "REGISTRATION_REJECT";
      break;
    case MessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING:
      str = "DEREGISTRATION_REQUEST_UE_ORIGINATING";
      break;
    case MessageType::DEREGISTRATION_ACCEPT_UE_ORIGINATING:
      str = "DEREGISTRATION_ACCEPT_UE_ORIGINATING";
      break;
    case MessageType::DEREGISTRATION_REQUEST_UE_TERMINATED:
      str = "DEREGISTRATION_REQUEST_UE_TERMINATED";
      break;
    case MessageType::DEREGISTRATION_ACCEPT_UE_TERMINATED:
      str = "DEREGISTRATION_ACCEPT_UE_TERMINATED";
      break;
    case MessageType::SERVICE_REQUEST:
      str = "SERVICE_REQUEST";
      break;
    case MessageType::SERVICE_REJECT:
      str = "SERVICE_REJECT";
      break;
    case MessageType::SERVICE_ACCEPT:
      str = "SERVICE_ACCEPT";
      break;
    case MessageType::CONFIGURATION_UPDATE_COMMAND:
      str = "CONFIGURATION_UPDATE_COMMAND";
      break;
    case MessageType::CONFIGURATION_UPDATE_COMPLETE:
      str = "CONFIGURATION_UPDATE_COMPLETE";
      break;
    case MessageType::AUTHENTICATION_REQUEST:
      str = "AuthenticationRequest";
      break;
    case MessageType::AUTHENTICATION_RESPONSE:
      str = "AUTHENTICATION_REQUEST";
      break;
    case MessageType::AUTHENTICATION_REJECT:
      str = "AUTHENTICATION_REJECT";
      break;
    case MessageType::AUTHENTICATION_FAILURE:
      str = "AUTHENTICATION_FAILURE";
      break;
    case MessageType::AUTHENTICATION_RESULT:
      str = "AUTHENTICATION_RESULT";
      break;
    case MessageType::IDENTITY_REQUEST:
      str = "IDENTITY_REQUEST";
      break;
    case MessageType::IDENTITY_RESPONSE:
      str = "IDENTITY_RESPONSE";
      break;
    case MessageType::SECURITY_MODE_COMMAND:
      str = "SECURITY_MODE_COMMAND";
      break;
    case MessageType::SECURITY_MODE_COMPLETE:
      str = "SECURITY_MODE_COMPLETE";
      break;
    case MessageType::SECURITY_MODE_REJECT:
      str = "SECURITY_MODE_REJECT";
      break;
    case MessageType::FIVEG_MM_STATUS:
      str = "FIVEG_MM_STATUS";
      break;
    case MessageType::NOTIFICATION:
      str = "NOTIFICATION";
      break;
    case MessageType::NOTIFICATION_RESPONSE:
      str = "NOTIFICATION_RESPONSE";
      break;
    case MessageType::UL_NAS_TRANSPORT:
      str = "UL_NAS_TRANSPORT";
      break;
    case MessageType::DL_NAS_TRANSPORT:
      str = "DL_NAS_TRANSPORT";
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_REQUEST:
      str = "PDU_SESSION_ESTABLISHMENT_REQUEST";
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT:
      str = "PDU_SESSION_ESTABLISHMENT_ACCEPT";
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_REJECT:
      str = "PDU_SESSION_ESTABLISHMENT_REJECT";
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_COMMAND:
      str = "PDU_SESSION_AUTHENTICATION_COMMAND";
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_COMPLETE:
      str = "PDU_SESSION_AUTHENTICATION_COMPLETE";
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_RESULT:
      str = "PDU_SESSION_AUTHENTICATION_RESULT";
      break;
    case MessageType::PDU_SESSION_MODIFICATION_REQUEST:
      str = "PDU_SESSION_MODIFICATION_REQUEST";
      break;
    case MessageType::PDU_SESSION_MODIFICATION_REJECT:
      str = "PDU_SESSION_MODIFICATION_REJECT";
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMMAND:
      str = "PDU_SESSION_MODIFICATION_COMMAND";
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMPLETE:
      str = "PDU_SESSION_MODIFICATION_COMPLETE";
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMMAND_REJECT:
      str = "PDU_SESSION_MODIFICATION_COMMAND_REJECT";
      break;
    case MessageType::PDU_SESSION_RELEASE_REQUEST:
      str = "PDU_SESSION_RELEASE_REQUEST";
      break;
    case MessageType::PDU_SESSION_RELEASE_REJECT:
      str = "PDU_SESSION_RELEASE_REJECT";
      break;
    case MessageType::PDU_SESSION_RELEASE_COMMAND:
      str = "PDU_SESSION_RELEASE_COMMAND";
      break;
    case MessageType::PDU_SESSION_RELEASE_COMPLETE:
      str = "PDU_SESSION_RELEASE_COMPLETE";
      break;
    case MessageType::FIVEG_SM_STATUS:
      str = "FIVEG_SM_STATUS";
      break;
    default:
      str = "?";
      break;
    }
    return str;
  }
  static std::string Enum2String(InformationElementType ieitype) {
    std::string str;
    switch (ieitype) {
      case InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR: {
        str = "ExtendedProtocolDiscriminator";
        break;
      }
      case InformationElementType::IE_SECURITY_HEADER_TYPE: {
        str = "SecurityHeaderType";
        break;
      }
      case InformationElementType::IE_PDU_SESSION_ID: {
        str = "PduSessionId";
        break;
      }
      case InformationElementType::IE_SPARE_HALF_OCTET: {
        str = "SpareHalfOctet";
        break;
      }
      case InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY: {
        str = "ProcedureTransactionIdentity";
        break;
      }
      case InformationElementType::IE_MESSAGE_TYPE: {
        str = "MessageType";
        break;
      }
      case InformationElementType::IE_MESSAGE_AUTHENTICATION_CODE: {
        str = "MessageAuthenticationCode";
        break;
      }
      case InformationElementType::IE_SEQUENCE_NUMBER: {
        str = "SequenceNumber";
        break;
      }
      case InformationElementType::IE_ADDITIONAL_INFORMATION: {
        str = "AdditionalInformation";
        break;
      }
      case InformationElementType::IE_ACCESS_TYPE: {
        str = "AccessType";
        break;
      }
      case InformationElementType::IE_DNN: {
        str = "Dnn";
        break;
      }
      case InformationElementType::IE_EAP_MESSAGE: {
        str = "EapMessage";
        break;
      }
      case InformationElementType::IE_GPRS_TIMER: {
        str = "GprsTimer";
        break;
      }
      case InformationElementType::IE_GPRS_TIMER_2: {
        str = "GprsTimer2";
        break;
      }
      case InformationElementType::IE_GPRS_TIMER_3: {
        str = "GprsTimer3";
        break;
      }
      case InformationElementType::IE_INTRA_N1_MODE_NAS_TRANSPARENT_CONTAINER: {
        str = "IntraN1ModeNasTransparentContainer";
        break;
      }
      case InformationElementType::
          IE_N1_MODE_TO_S1_MODE_NAS_TRANSPARENT_CONTAINER: {
        str = "N1ModeToS1ModeNasTransparentContainer";
        break;
      }
      case InformationElementType::IE_S_NSSAI: {
        str = "SNssai";
        break;
      }
      case InformationElementType::
          IE_S1_MODE_TO_N1_MODE_NAS_TRANSPARENT_CONTAINER: {
        str = "S1ModeToN1ModeNasTransparentContainer";
        break;
      }
      case InformationElementType::IE_5GMM_CAPABILITY: {
        str = "FiveGmmCapability";
        break;
      }
      case InformationElementType::IE_5GMM_CAUSE: {
        str = "FiveGmmCause";
        break;
      }
      case InformationElementType::IE_5GS_DRX_PARAMETERS: {
        str = "FiveGsDrxParameters";
        break;
      }
      case InformationElementType::IE_5GS_IDENTITY_TYPE: {
        str = "FiveGsIdentityType";
        break;
      }
      case InformationElementType::IE_5GS_MOBILE_IDENTITY: {
        str = "MobileIdentity";
        break;
      }
      case InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT: {
        str = "FiveGsNetworkFeatureSupport";
        break;
      }
      case InformationElementType::IE_5GS_REGISTRATION_RESULT: {
        str = "FiveGsRegistrationResult";
        break;
      }
      case InformationElementType::IE_5GS_REGISTRATION_TYPE: {
        str = "FiveGSRegistrationType";
        break;
      }
      case InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY: {
        str = "FiveGsTrackingAreaIdentity";
        break;
      }
      case InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY_LIST: {
        str = "FiveGsTrackingAreaIdentityList";
        break;
      }
      case InformationElementType::IE_5GS_UPDATE_TYPE: {
        str = "FiveGsUpdateType";
        break;
      }
      case InformationElementType::IE_ABBA: {
        str = "Abba";
        break;
      }
      case InformationElementType::IE_ADDITIONAL_5G_SECURITY_INFORMATION: {
        str = "Additional5GSecurityInformation";
        break;
      }
      case InformationElementType::IE_ADDITIONAL_INFORMATION_REQUESTED: {
        str = "AdditionalInformationRequested";
        break;
      }
      case InformationElementType::IE_ALLOWED_PDU_SESSION_STATUS: {
        str = "AllowedPduSessionStatus";
        break;
      }
      case InformationElementType::IE_AUTHENTICATION_FAILURE_PARAMETER: {
        str = "AuthenticationFailureParameter";
        break;
      }
      case InformationElementType::IE_AUTHENTICATION_PARAMETER_AUTN: {
        str = "AuthenticationParameterAutn";
        break;
      }
      case InformationElementType::IE_AUTHENTICATION_PARAMETER_RAND: {
        str = "AuthenticationParameterRand";
        break;
      }
      case InformationElementType::IE_AUTHENTICATION_RESPONSE_PARAMETER: {
        str = "AuthenticationResponseParameter";
        break;
      }
      case InformationElementType::IE_CONFIGURATION_UPDATE_INDICATION: {
        str = "ConfigurationUpdateIndication";
        break;
      }
      case InformationElementType::IE_CAG_INFORMATION_LIST: {
        str = "CagInformationList";
        break;
      }
      case InformationElementType::IE_CIOT_SMALL_DATA_CONTAINER: {
        str = "CiotSmallDataContainer";
        break;
      }
      case InformationElementType::IE_CIPHERING_KEY_DATA: {
        str = "CipheringKeyData";
        break;
      }
      case InformationElementType::IE_CONTROL_PLANE_SERVICE_TYPE: {
        str = "ControlPlaneServiceType";
        break;
      }
      case InformationElementType::IE_DAYLIGHT_SAVING_TIME: {
        str = "DaylightSavingTime";
        break;
      }
      case InformationElementType::IE_DEREGISTRATION_TYPE: {
        str = "DeRegistrationType";
        break;
      }
      case InformationElementType::IE_EMERGENCY_NUMBER_LIST: {
        str = "EmergencyNumberList";
        break;
      }
      case InformationElementType::IE_EPS_BEARER_CONTEXT_STATUS: {
        str = "EpsBearerContextStatus";
        break;
      }
      case InformationElementType::IE_EPS_NAS_MESSAGE_CONTAINER: {
        str = "EpsNasMessageContainer";
        break;
      }
      case InformationElementType::IE_EPS_NAS_SECURITY_ALGORITHMS: {
        str = "EpsNasSecurityAlgorithms";
        break;
      }
      case InformationElementType::IE_EXTENDED_EMERGENCY_NUMBER_LIST: {
        str = "ExtendedEmergencyNumberList";
        break;
      }
      case InformationElementType::IE_EXTENDED_DRX_PARAMETERS: {
        str = "ExtendedDrxParameters";
        break;
      }
      case InformationElementType::IE_IMEISV_REQUEST: {
        str = "ImeisvRequest";
        break;
      }
      case InformationElementType::IE_LADN_INDICATION: {
        str = "LadnIndication";
        break;
      }
      case InformationElementType::IE_LADN_INFORMATION: {
        str = "LadnInformation";
        break;
      }
      case InformationElementType::IE_MICO_INDICATION: {
        str = "MicoIndication";
        break;
      }
      case InformationElementType::IE_MA_PDU_SESSION_INFORMATION: {
        str = "MaPduSessionInformation";
        break;
      }
      case InformationElementType::IE_MAPPED_NSSAI: {
        str = "MappedNssai";
        break;
      }
      case InformationElementType::IE_MOBILE_STATION_CLASSMARK_2: {
        str = "MobileStationClassmark2";
        break;
      }
      case InformationElementType::IE_NAS_KEY_SET_IDENTIFIER: {
        str = "NasKeySetIdentifier";
        break;
      }
      case InformationElementType::IE_NAS_MESSAGE_CONTAINER: {
        str = "NasMessageContainer";
        break;
      }
      case InformationElementType::IE_NAS_SECURITY_ALGORITHMS: {
        str = "NasSecurityAlgorithms";
        break;
      }
      case InformationElementType::IE_SELECTED_NAS_SECURITY_ALGORITHMS: {
        str = "SelectedNasSecurityAlgorithms";
        break;
      }
      case InformationElementType::IE_NETWORK_NAME: {
        str = "NetworkName";
        break;
      }
      case InformationElementType::IE_NETWORK_SLICING_INDICATION: {
        str = "NetworkSlicingIndication";
        break;
      }
      case InformationElementType::IE_NON_3GPP_NW_PROVIDED_POLICIES: {
        str = "Non3GppNwProvidedPolicies";
        break;
      }
      case InformationElementType::IE_NSSAI: {
        str = "SNssai";
        break;
      }
      case InformationElementType::IE_NSSAI_INCLUSION_MODE: {
        str = "NssaiInclusionMode";
        break;
      }
      case InformationElementType::
          IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS: {
        str = "OperatorDefinedAccessCategoryDefinitions";
        break;
      }
      case InformationElementType::IE_PAYLOAD_CONTAINER: {
        str = "PayloadContainer";
        break;
      }
      case InformationElementType::IE_PAYLOAD_CONTAINER_TYPE: {
        str = "PayloadContainerType";
        break;
      }
      case InformationElementType::IE_PDU_SESSION_IDENTITY_2: {
        str = "PduSessionIdentity2";
        break;
      }
      case InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT: {
        str = "PduSessionReactivationResult";
        break;
      }
      case InformationElementType::
          IE_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE: {
        str = "PduSessionReactivationResultErrorCause";
        break;
      }
      case InformationElementType::IE_PDU_SESSION_STATUS: {
        str = "PduSessionStatus";
        break;
      }
      case InformationElementType::IE_PLMN_LIST: {
        str = "PlmnList";
        break;
      }
      case InformationElementType::IE_REJECTED_NSSAI: {
        str = "RejectedNssai";
        break;
      }
      case InformationElementType::IE_RELEASE_ASSISTANCE_INDICATION: {
        str = "ReleaseAssistanceIndication";
        break;
      }
      case InformationElementType::IE_REQUEST_TYPE: {
        str = "RequestType";
        break;
      }
      case InformationElementType::IE_S1_UE_NETWORK_CAPABILITY: {
        str = "S1UeNetworkCapability";
        break;
      }
      case InformationElementType::IE_S1_UE_SECURITY_CAPABILITY: {
        str = "S1UeSecurityCapability";
        break;
      }
      case InformationElementType::IE_SERVICE_AREA_LIST: {
        str = "ServiceAreaList";
        break;
      }
      case InformationElementType::IE_SERVICE_TYPE: {
        str = "ServiceType";
        break;
      }
      case InformationElementType::IE_SMS_INDICATION: {
        str = "SmsIndication";
        break;
      }
      case InformationElementType::IE_SOR_TRANSPARENT_CONTAINER: {
        str = "SorTransparentContainer";
        break;
      }
      case InformationElementType::IE_SUPPORTED_CODEC_LIST: {
        str = "SupportedCodecList";
        break;
      }
      case InformationElementType::IE_TIME_ZONE: {
        str = "TimeZone";
        break;
      }
      case InformationElementType::IE_TIME_ZONE_AND_TIME: {
        str = "TimeZoneAndTime";
        break;
      }
      case InformationElementType::
          IE_UE_PARAMETERS_UPDATE_TRANSPARENT_CONTAINER: {
        str = "UeParametersUpdateTransparentContainer";
        break;
      }
      case InformationElementType::IE_UE_SECURITY_CAPABILITY: {
        str = "UeSecurityCapability";
        break;
      }
      case InformationElementType::IE_REPLAYED_UE_SECURITY_CAPABILITY: {
        str = "ReplayedUeSecurityCapability";
        break;
      }
      case InformationElementType::IE_UE_USAGE_SETTING: {
        str = "UeUsageSetting";
        break;
      }
      case InformationElementType::IE_UE_STATUS: {
        str = "UeStatus";
        break;
      }
      case InformationElementType::IE_UPLINK_DATA_STATUS: {
        str = "UplinkDataStatus";
        break;
      }
      case InformationElementType::IE_UE_RADIO_CAPABILITY_ID: {
        str = "UeRadioCapabilityId";
        break;
      }
      case InformationElementType::
          IE_UE_RADIO_CAPABILITY_ID_DELETION_INDICATION: {
        str = "UeRadioCapabilityIdDeletionIndication";
        break;
      }
      case InformationElementType::IE_TRUNCATED_5G_S_TMSI_CONFIGURATION: {
        str = "Truncated5GSTmsiConfiguration";
        break;
      }
      case InformationElementType::IE_WUS_ASSISTANCE_INFORMATION: {
        str = "WusAssistanceInformation";
        break;
      }
      case InformationElementType::IE_N5GC_INDICATION: {
        str = "N5GcIndication";
        break;
      }
      case InformationElementType::IE_NB_N1_MODE_DRX_PARAMETERS: {
        str = "NbN1ModeDrxParameters";
        break;
      }
      case InformationElementType::IE_ADDITIONAL_CONFIGURATION_INDICATION: {
        str = "AdditionalConfigurationIndication";
        break;
      }
      case InformationElementType::IE_5GSM_CAPABILITY: {
        str = "FiveGsmCapability";
        break;
      }
      case InformationElementType::IE_5GSM_CAUSE: {
        str = "FiveGsmCause";
        break;
      }
      case InformationElementType::IE_ALWAYS_ON_PDU_SESSION_INDICATION: {
        str = "AlwaysOnPduSessionIndication";
        break;
      }
      case InformationElementType::IE_ALWAYS_ON_PDU_SESSION_REQUESTED: {
        str = "AlwaysOnPduSessionRequested";
        break;
      }
      case InformationElementType::IE_ALLOWED_SSC_MODE: {
        str = "AllowedSscMode";
        break;
      }
      case InformationElementType::IE_SELECTED_SSC_MODE: {
        str = "SelectedSscMode";
        break;
      }
      case InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS: {
        str = "ExtendedProtocolConfigurationOptions";
        break;
      }
      case InformationElementType::IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE: {
        str = "IntegrityProtectionMaximumDataRate";
        break;
      }
      case InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS: {
        str = "MappedEpsBearerContexts";
        break;
      }
      case InformationElementType::
          IE_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS: {
        str = "MaximumNumberOfSupportedPacketFilters";
        break;
      }
      case InformationElementType::IE_PDU_ADDRESS: {
        str = "PduAddress";
        break;
      }
      case InformationElementType::IE_PDU_SESSION_TYPE: {
        str = "PduSessionType";
        break;
      }
      case InformationElementType::IE_SELECTED_PDU_SESSION_TYPE: {
        str = "SelectedPduSessionType";
        break;
      }
      case InformationElementType::IE_QOS_FLOW_DESCRIPTIONS: {
        str = "QosFlowDescriptions";
        break;
      }
      case InformationElementType::IE_QOS_RULES: {
        str = "QosRules";
        break;
      }
      case InformationElementType::IE_SESSION_AMBR: {
        str = "SessionAmbr";
        break;
      }
      case InformationElementType::IE_SM_PDU_DN_REQUEST_CONTAINER: {
        str = "SmPduDnRequestContainer";
        break;
      }
      case InformationElementType::IE_SSC_MODE: {
        str = "SscMode";
        break;
      }
      case InformationElementType::IE_RE_ATTEMPT_INDICATOR: {
        str = "ReAttemptIndicator";
        break;
      }
      case InformationElementType::IE_SERVING_PLMN_RATE_CONTROL: {
        str = "ServingPlmnRateControl";
        break;
      }
      case InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR: {
        str = "FiveGsmCongestionReAttemptIndicator";
        break;
      }
      case InformationElementType::IE_ATSSS_CONTAINER: {
        str = "AtsssContainer";
        break;
      }
      case InformationElementType::IE_CONTROL_PLANE_ONLY_INDICATION: {
        str = "ControlPlaneOnlyIndication";
        break;
      }
      case InformationElementType::IE_IP_HEADER_COMPRESSION_CONFIGURATION: {
        str = "IpHeaderCompressionConfiguration";
        break;
      }
      case InformationElementType::IE_DS_TT_ETHERNET_PORT_MAC_ADDRESS: {
        str = "DsTtEthernetPortMacAddress";
        break;
      }
      case InformationElementType::IE_UE_DS_TT_RESIDENCE_TIME: {
        str = "UeDsTtResidenceTime";
        break;
      }
      case InformationElementType::IE_PORT_MANAGEMENT_INFORMATION_CONTAINER: {
        str = "PortManagementInformationContainer";
        break;
      }
      case InformationElementType::IE_ETHERNET_HEADER_COMPRESSION_CONFIGURATION: {
        str = "EthernetHeaderCompressionConfiguration";
        break;
      }
      case InformationElementType::IE_LAST_VISITED_REGISTERED_TRACKING_AREA_IDENTITY: {
        str = "LastVisitedRegisteredTai";
      break;
      }
        case InformationElementType::IE_5G_GUTI: {
          str = "FiveGGuti";
      break;
      }
        case InformationElementType::IE_ADDITIONAL_GUTI: {
          str = "AdditionalGuti";
      break;
      }
        case InformationElementType::IE_ALLOWED_NSSAI: {
          str = "AllowedNssai";
      break;
      }
        case InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS: {
          str = "AuthorizedQosFlowDescriptions";
      break;
      }
        case InformationElementType::IE_AUTHORIZED_QOS_RULES: {
          str = "AuthorizedQosRules";
      break;
      }
        case InformationElementType::IE_BACK_OFF_TIMER_VALUE: {
          str = "BackOffTimerValue";
      break;
      }
        case InformationElementType::IE_CONFIGURED_NSSAI: {
          str = "ConfiguredNssai";
      break;
      }
        case InformationElementType::IE_EQUIVALENT_PLMN_LIST: {
          str = "EquivalentPlmns";
      break;
      }
        case InformationElementType::IE_FULL_NAME_OF_NETWORK: {
          str = "FullNameOfNetwork";
      break;
      }
        case InformationElementType::IE_IMEISV: {
          str = "ImeiSv";
      break;
      }
        case InformationElementType::IE_LOCAL_TIME_ZONE: {
          str = "LocalTimeZone";
      break;
      }
      case InformationElementType::IE_NAS_KEY_SET_IDENTIFIER_1: {
        str = "NasKeySetIdentifier";
      break;
      }
      case InformationElementType::IE_NEGOTIATED_DRX_PARAMETERS: {
        str = "NegotiatedDrxParameters";
      break;
      }
      case InformationElementType::IE_NETWORK_DAYLIGHT_SAVING_TIME: {
        str = "NetworkDaylightSavingTime";
      break;
      }
      case InformationElementType::IE_NON_3GPP_DEREGISTRATION_TIMER_VAL: {
        str = "Non3GPPDeregistrationTimerValue";
      break;
      }
        case InformationElementType::IE_NON_CURRENT_NATIVE_NAS_KEY_SET_IDENTIFIER: {
          str = "NonCurrentNativeNasKeySetIdentifier";
      break;
      }
        case InformationElementType::IE_OLD_PDU_SESSION_ID: {
          str = "OldPduSessionId";
      break;
      }
      case InformationElementType::IE_REPLAYED_S1_UE_SECURITY_CAPABILITY: {
        str = "ReplayedS1UeSecurityCapability";
      break;
      }
        case InformationElementType::IE_REQUESTED_DRX_PARAMETERS: {
          str = "RequestedDrxParameters";
      break;
      }
        case InformationElementType::IE_REQUESTED_NSSAI: {
          str = "RequestedNssai";
      break;
      }
        case InformationElementType::IE_REQUESTED_QOS_FLOW_DESCRIPTIONS: {
          str = "RequestedQosFlowDescriptions";
      break;
      }
        case InformationElementType::IE_REQUESTED_QOS_RULES: {
          str = "RequestedQosRules";
      break;
      }
        case InformationElementType::IE_RQ_TIMER_VALUE: {
          str = "RQTimerValue";
      break;
      }
        case InformationElementType::IE_SELECTED_EPS_NAS_SECURITY_ALGORITHMS: {
          str = "SelectedEpsNasSecurityAlgorithms";
      break;
      }
        case InformationElementType::IE_SHORT_NAME_OF_NETWORK: {
          str = "ShortNameOfNetwork";
      break;
      }
        case InformationElementType::IE_T3346_VALUE: {
          str = "T3346Value";
      break;
      }
        case InformationElementType::IE_T3502_VALUE: {
          str = "T3502Value";
      break;
      }
        case InformationElementType::IE_T3512_VALUE: {
          str = "T3512Value";
      break;
      }
        case InformationElementType::IE_UINVERSAL_TIME_AND_LOCAL_TIME_ZONE: {
          str = "UniversalTimeAndLocalTimeZone";
      break;
      }
      default: {
        break;
      }
    }
  
    return str;
  }

#if 0
const char *EnumToString(MmCause v)
{
    switch (v)
    {
    case MmCause::ILLEGAL_UE:
        return "ILLEGAL_UE";
    case MmCause::PEI_NOT_ACCEPTED:
        return "PEI_NOT_ACCEPTED";
    case MmCause::ILLEGAL_ME:
        return "ILLEGAL_ME";
    case MmCause::FIVEG_SERVICES_NOT_ALLOWED:
        return "FIVEG_SERVICES_NOT_ALLOWED";
    case MmCause::UE_IDENTITY_CANNOT_BE_DERIVED_FROM_NETWORK:
        return "UE_IDENTITY_CANNOT_BE_DERIVED_FROM_NETWORK";
    case MmCause::IMPLICITY_DEREGISTERED:
        return "IMPLICITY_DEREGISTERED";
    case MmCause::PLMN_NOT_ALLOWED:
        return "PLMN_NOT_ALLOWED";
    case MmCause::TA_NOT_ALLOWED:
        return "TA_NOT_ALLOWED";
    case MmCause::ROAMING_NOT_ALLOWED_IN_TA:
        return "ROAMING_NOT_ALLOWED_IN_TA";
    case MmCause::NO_SUITIBLE_CELLS_IN_TA:
        return "NO_SUITIBLE_CELLS_IN_TA";
    case MmCause::MAC_FAILURE:
        return "MAC_FAILURE";
    case MmCause::SYNCH_FAILURE:
        return "SYNCH_FAILURE";
    case MmCause::CONGESTION:
        return "CONGESTION";
    case MmCause::UE_SECURITY_CAP_MISMATCH:
        return "UE_SECURITY_CAP_MISMATCH";
    case MmCause::SEC_MODE_REJECTED_UNSPECIFIED:
        return "SEC_MODE_REJECTED_UNSPECIFIED";
    case MmCause::NON_5G_AUTHENTICATION_UNACCEPTABLE:
        return "NON_5G_AUTHENTICATION_UNACCEPTABLE";
    case MmCause::N1_MODE_NOT_ALLOWED:
        return "N1_MODE_NOT_ALLOWED";
    case MmCause::RESTRICTED_SERVICE_AREA:
        return "RESTRICTED_SERVICE_AREA";
    case MmCause::LADN_NOT_AVAILABLE:
        return "LADN_NOT_AVAILABLE";
    case MmCause::MAX_PDU_SESSIONS_REACHED:
        return "MAX_PDU_SESSIONS_REACHED";
    case MmCause::INSUFFICIENT_RESOURCES_FOR_SLICE_AND_DNN:
        return "INSUFFICIENT_RESOURCES_FOR_SLICE_AND_DNN";
    case MmCause::INSUFFICIENT_RESOURCES_FOR_SLICE:
        return "INSUFFICIENT_RESOURCES_FOR_SLICE";
    case MmCause::NGKSI_ALREADY_IN_USE:
        return "NGKSI_ALREADY_IN_USE";
    case MmCause::NON_3GPP_ACCESS_TO_CN_NOT_ALLOWED:
        return "NON_3GPP_ACCESS_TO_CN_NOT_ALLOWED";
    case MmCause::SERVING_NETWORK_NOT_AUTHORIZED:
        return "SERVING_NETWORK_NOT_AUTHORIZED";
    case MmCause::PAYLOAD_NOT_FORWARDED:
        return "PAYLOAD_NOT_FORWARDED";
    case MmCause::DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED:
        return "DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED";
    case MmCause::INSUFFICIENT_USER_PLANE_RESOURCES:
        return "INSUFFICIENT_USER_PLANE_RESOURCES";
    case MmCause::SEMANTICALLY_INCORRECT_MESSAGE:
        return "SEMANTICALLY_INCORRECT_MESSAGE";
    case MmCause::INVALID_MANDATORY_INFORMATION:
        return "INVALID_MANDATORY_INFORMATION";
    case MmCause::MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED:
        return "MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED";
    case MmCause::MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE:
        return "MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE";
    case MmCause::INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED:
        return "INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED";
    case MmCause::CONDITIONAL_IE_ERROR:
        return "CONDITIONAL_IE_ERROR";
    case MmCause::MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE:
        return "MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE";
    case MmCause::UNSPECIFIED_PROTOCOL_ERROR:
        return "UNSPECIFIED_PROTOCOL_ERROR";
    default:
        return "?";
    }
}

const char *EnumToString(eap::ECode v)
{
    switch (v)
    {
    case eap::ECode::REQUEST:
        return "REQUEST";
    case eap::ECode::RESPONSE:
        return "RESPONSE";
    case eap::ECode::SUCCESS:
        return "SUCCESS";
    case eap::ECode::FAILURE:
        return "FAILURE";
    case eap::ECode::INITIATE:
        return "INITIATE";
    case eap::ECode::FINISH:
        return "FINISH";
    default:
        return "?";
    }
}

const char *EnumToString(ESmCause v)
{
    switch (v)
    {
    case ESmCause::INSUFFICIENT_RESOURCES:
        return "INSUFFICIENT_RESOURCES";
    case ESmCause::MISSING_OR_UNKNOWN_DNN:
        return "MISSING_OR_UNKNOWN_DNN";
    case ESmCause::UNKNOWN_PDU_SESSION_TYPE:
        return "UNKNOWN_PDU_SESSION_TYPE";
    case ESmCause::USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED:
        return "USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED";
    case ESmCause::REQUEST_REJECTED_UNSPECIFIED:
        return "REQUEST_REJECTED_UNSPECIFIED";
    case ESmCause::SERVICE_OPTION_TEMPORARILY_OUT_OF_ORDER:
        return "SERVICE_OPTION_TEMPORARILY_OUT_OF_ORDER";
    case ESmCause::PTI_ALREADY_IN_USE:
        return "PTI_ALREADY_IN_USE";
    case ESmCause::REGULAR_DEACTIVATION:
        return "REGULAR_DEACTIVATION";
    case ESmCause::REACTIVATION_REQUESTED:
        return "REACTIVATION_REQUESTED";
    case ESmCause::INVALID_PDU_SESSION_IDENTITY:
        return "INVALID_PDU_SESSION_IDENTITY";
    case ESmCause::SEMANTIC_ERRORS_IN_PACKET_FILTERS:
        return "SEMANTIC_ERRORS_IN_PACKET_FILTERS";
    case ESmCause::SYNTACTICAL_ERROR_IN_PACKET_FILTERS:
        return "SYNTACTICAL_ERROR_IN_PACKET_FILTERS";
    case ESmCause::OUT_OF_LADN_SERVICE_AREA:
        return "OUT_OF_LADN_SERVICE_AREA";
    case ESmCause::PTI_MISMATCH:
        return "PTI_MISMATCH";
    case ESmCause::PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED:
        return "PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED";
    case ESmCause::PDU_SESSION_TYPE_IPV6_ONLY_ALLOWED:
        return "PDU_SESSION_TYPE_IPV6_ONLY_ALLOWED";
    case ESmCause::PDU_SESSION_DOES_NOT_EXIST:
        return "PDU_SESSION_DOES_NOT_EXIST";
    case ESmCause::INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN:
        return "INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN";
    case ESmCause::NOT_SUPPORTED_SSC_MODE:
        return "NOT_SUPPORTED_SSC_MODE";
    case ESmCause::INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE:
        return "INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE";
    case ESmCause::MISSING_OR_UNKNOWN_DNN_IN_A_SLICE:
        return "MISSING_OR_UNKNOWN_DNN_IN_A_SLICE";
    case ESmCause::INVALID_PTI_VALUE:
        return "INVALID_PTI_VALUE";
    case ESmCause::MAXIMUM_DATA_RATE_PER_UE_FOR_USER_PLANE_INTEGRITY_PROTECTION_IS_TOO_LOW:
        return "MAXIMUM_DATA_RATE_PER_UE_FOR_USER_PLANE_INTEGRITY_PROTECTION_IS_TOO_LOW";
    case ESmCause::SEMANTIC_ERROR_IN_THE_QOS_OPERATION:
        return "SEMANTIC_ERROR_IN_THE_QOS_OPERATION";
    case ESmCause::SYNTACTICAL_ERROR_IN_THE_QOS_OPERATION:
        return "SYNTACTICAL_ERROR_IN_THE_QOS_OPERATION";
    case ESmCause::SEMANTICALLY_INCORRECT_MESSAGE:
        return "SEMANTICALLY_INCORRECT_MESSAGE";
    case ESmCause::INVALID_MANDATORY_INFORMATION:
        return "INVALID_MANDATORY_INFORMATION";
    case ESmCause::MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED:
        return "MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED";
    case ESmCause::MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE:
        return "MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE";
    case ESmCause::INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED:
        return "INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED";
    case ESmCause::CONDITIONAL_IE_ERROR:
        return "CONDITIONAL_IE_ERROR";
    case ESmCause::MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE:
        return "MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE";
    case ESmCause::PROTOCOL_ERROR_UNSPECIFIED:
        return "PROTOCOL_ERROR_UNSPECIFIED";
    default:
        return "?";
    }
}

const char *EnumToString(EPduSessionType v)
{
    switch (v)
    {
    case EPduSessionType::IPV4:
        return "IPV4";
    case EPduSessionType::IPV6:
        return "IPV6";
    case EPduSessionType::IPV4V6:
        return "IPV4V6";
    case EPduSessionType::UNSTRUCTURED:
        return "UNSTRUCTURED";
    case EPduSessionType::ETHERNET:
        return "ETHERNET";
    default:
        return "?";
    }
}
#endif
  static void
  GetSupportedSecurityIEs(std::vector<InformationElementType> &securityIEs) {
    securityIEs = {
        InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
        InformationElementType::IE_SECURITY_HEADER_TYPE,
        InformationElementType::IE_SPARE_HALF_OCTET,
        InformationElementType::IE_MESSAGE_AUTHENTICATION_CODE,
        InformationElementType::IE_SEQUENCE_NUMBER,
    };
  }
  static void
  GetSupportedMandatoryIEs(MessageType msgtype,
                           std::vector<InformationElementType> &mandatoryIEs) {
    switch (msgtype) {
    case MessageType::REGISTRATION_REQUEST:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GS_REGISTRATION_TYPE,
          InformationElementType::IE_NAS_KEY_SET_IDENTIFIER,
          InformationElementType::IE_5GS_MOBILE_IDENTITY,
      };
      break;
    case MessageType::REGISTRATION_ACCEPT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GS_REGISTRATION_RESULT,
      };
      break;
    case MessageType::REGISTRATION_COMPLETE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,     
      };
      break;
    case MessageType::REGISTRATION_REJECT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GMM_CAUSE,      
      };
      break;
    case MessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_DEREGISTRATION_TYPE,
          InformationElementType::IE_NAS_KEY_SET_IDENTIFIER,
          InformationElementType::IE_5GS_MOBILE_IDENTITY,        
      };
      break;
    case MessageType::DEREGISTRATION_ACCEPT_UE_ORIGINATING:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,       
      };
      break;
    case MessageType::DEREGISTRATION_REQUEST_UE_TERMINATED:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_DEREGISTRATION_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
      };
      break;
    case MessageType::DEREGISTRATION_ACCEPT_UE_TERMINATED:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,          
      };
      break;
    case MessageType::SERVICE_REQUEST:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_NAS_KEY_SET_IDENTIFIER,
          InformationElementType::IE_SERVICE_TYPE,
          InformationElementType::IE_5GS_MOBILE_IDENTITY,
      };
      break;
    case MessageType::SERVICE_REJECT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GMM_CAUSE,
      };
      break;
    case MessageType::SERVICE_ACCEPT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::CONFIGURATION_UPDATE_COMMAND:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::CONFIGURATION_UPDATE_COMPLETE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::AUTHENTICATION_REQUEST:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_NAS_KEY_SET_IDENTIFIER,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_ABBA,
      };
      break;
    case MessageType::AUTHENTICATION_RESPONSE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::AUTHENTICATION_REJECT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::AUTHENTICATION_FAILURE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GMM_CAUSE,
      };
      break;
    case MessageType::AUTHENTICATION_RESULT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_NAS_KEY_SET_IDENTIFIER,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_EAP_MESSAGE,
      };
      break;
    case MessageType::IDENTITY_REQUEST:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GS_IDENTITY_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
      };
      break;
    case MessageType::IDENTITY_RESPONSE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GS_MOBILE_IDENTITY,
      };
      break;
    case MessageType::SECURITY_MODE_COMMAND:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_SELECTED_NAS_SECURITY_ALGORITHMS,
          InformationElementType::IE_NAS_KEY_SET_IDENTIFIER,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_REPLAYED_UE_SECURITY_CAPABILITY,    
      };
      break;
    case MessageType::SECURITY_MODE_COMPLETE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,        
      };
      break;
    case MessageType::SECURITY_MODE_REJECT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GMM_CAUSE,       
      };
      break;
    case MessageType::FIVEG_MM_STATUS:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GMM_CAUSE,   
      };
      break;
    case MessageType::NOTIFICATION:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_ACCESS_TYPE,   
          InformationElementType::IE_SPARE_HALF_OCTET,
      };
      break;
    case MessageType::NOTIFICATION_RESPONSE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::UL_NAS_TRANSPORT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_PAYLOAD_CONTAINER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_PAYLOAD_CONTAINER, 
      };
      break;
    case MessageType::DL_NAS_TRANSPORT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_SECURITY_HEADER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_PAYLOAD_CONTAINER_TYPE,
          InformationElementType::IE_SPARE_HALF_OCTET,
          InformationElementType::IE_PAYLOAD_CONTAINER, 
      };
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_REQUEST:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE,
      };
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_SELECTED_PDU_SESSION_TYPE,
          InformationElementType::IE_SELECTED_SSC_MODE,
          InformationElementType::IE_AUTHORIZED_QOS_RULES,
          InformationElementType::IE_SESSION_AMBR,
      };
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_REJECT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE, 
          InformationElementType::IE_5GSM_CAUSE,       
      };
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_COMMAND:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_EAP_MESSAGE, 
      };
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_COMPLETE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_EAP_MESSAGE, 
      };
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_RESULT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::PDU_SESSION_MODIFICATION_REQUEST:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::PDU_SESSION_MODIFICATION_REJECT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GSM_CAUSE, 
      };
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMMAND:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMPLETE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE, 
      };
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMMAND_REJECT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GSM_CAUSE, 
      };
      break;
    case MessageType::PDU_SESSION_RELEASE_REQUEST:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::PDU_SESSION_RELEASE_REJECT:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GSM_CAUSE, 
      };
      break;
    case MessageType::PDU_SESSION_RELEASE_COMMAND:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GSM_CAUSE, 
      };
      break;
    case MessageType::PDU_SESSION_RELEASE_COMPLETE:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
      };
      break;
    case MessageType::FIVEG_SM_STATUS:
      mandatoryIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR,
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY,
          InformationElementType::IE_MESSAGE_TYPE,
          InformationElementType::IE_5GSM_CAUSE,         
      };
      break;
    default:
      break;
    }
  }
  static void GetSupportedOptionalIEs(
      MessageType msgtype,
      std::unordered_set<InformationElementType> &optionalIEs) {
    switch (msgtype) {
    case MessageType::REGISTRATION_REQUEST:
      optionalIEs = {
        InformationElementType::IE_NON_CURRENT_NATIVE_NAS_KEY_SET_IDENTIFIER,
        InformationElementType::IE_5GMM_CAPABILITY,
        InformationElementType::IE_UE_SECURITY_CAPABILITY,
        InformationElementType::IE_REQUESTED_NSSAI,
        InformationElementType::IE_LAST_VISITED_REGISTERED_TRACKING_AREA_IDENTITY,
        InformationElementType::IE_S1_UE_NETWORK_CAPABILITY,
        InformationElementType::IE_UPLINK_DATA_STATUS,
        InformationElementType::IE_PDU_SESSION_STATUS,
        InformationElementType::IE_MICO_INDICATION,
        InformationElementType::IE_UE_STATUS,
        InformationElementType::IE_ADDITIONAL_GUTI,
        InformationElementType::IE_ALLOWED_PDU_SESSION_STATUS,
        InformationElementType::IE_UE_USAGE_SETTING,
        InformationElementType::IE_REQUESTED_DRX_PARAMETERS,
        InformationElementType::IE_EPS_NAS_MESSAGE_CONTAINER,
        InformationElementType::IE_LADN_INDICATION,
        InformationElementType::IE_PAYLOAD_CONTAINER_TYPE,
        InformationElementType::IE_PAYLOAD_CONTAINER,
        InformationElementType::IE_NETWORK_SLICING_INDICATION,
        InformationElementType::IE_5GS_UPDATE_TYPE,
        InformationElementType::IE_NAS_MESSAGE_CONTAINER,
        InformationElementType::IE_EPS_BEARER_CONTEXT_STATUS
      };
      break;
    case MessageType::REGISTRATION_ACCEPT:
      optionalIEs = {
        InformationElementType::IE_5G_GUTI,
        InformationElementType::IE_EQUIVALENT_PLMN_LIST,
        InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY_LIST,
        InformationElementType::IE_ALLOWED_NSSAI,
        InformationElementType::IE_REJECTED_NSSAI,
        InformationElementType::IE_REJECTED_NSSAI,
        InformationElementType::IE_CONFIGURED_NSSAI,
        InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT,
        InformationElementType::IE_PDU_SESSION_STATUS,
        InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT,
        InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE,
        InformationElementType::IE_LADN_INFORMATION,
        InformationElementType::IE_MICO_INDICATION,
        InformationElementType::IE_NETWORK_SLICING_INDICATION,
        InformationElementType::IE_SERVICE_AREA_LIST,
        InformationElementType::IE_T3512_VALUE,
        InformationElementType::IE_NON_3GPP_DEREGISTRATION_TIMER_VAL,
        InformationElementType::IE_T3502_VALUE,
        InformationElementType::IE_EXTENDED_EMERGENCY_NUMBER_LIST,
        InformationElementType::IE_EXTENDED_EMERGENCY_NUMBER_LIST,
        InformationElementType::IE_SOR_TRANSPARENT_CONTAINER,
        InformationElementType::IE_EAP_MESSAGE,
        InformationElementType::IE_NSSAI_INCLUSION_MODE,
        InformationElementType::IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS,
        InformationElementType::IE_NEGOTIATED_DRX_PARAMETERS,
        InformationElementType::IE_NON_3GPP_NW_PROVIDED_POLICIES,
        InformationElementType::IE_EPS_BEARER_CONTEXT_STATUS,
      };
      break;
    case MessageType::REGISTRATION_COMPLETE:
      optionalIEs = {
          InformationElementType::IE_SOR_TRANSPARENT_CONTAINER,
      };
      break;
    case MessageType::REGISTRATION_REJECT:
      optionalIEs = {
          InformationElementType::IE_T3346_VALUE,
          InformationElementType::IE_T3502_VALUE, 
          InformationElementType::IE_EAP_MESSAGE,  
      };
      break;
    case MessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING:
      optionalIEs = {

			};
      break;
    case MessageType::DEREGISTRATION_ACCEPT_UE_ORIGINATING:
      optionalIEs = {

			};
      break;
    case MessageType::DEREGISTRATION_REQUEST_UE_TERMINATED:
      optionalIEs = {
        InformationElementType::IE_5GMM_CAUSE,
        InformationElementType::IE_T3346_VALUE,
			};
      break;
    case MessageType::DEREGISTRATION_ACCEPT_UE_TERMINATED:
      optionalIEs = {

			};
      break;
    case MessageType::SERVICE_REQUEST:
      optionalIEs = {
        InformationElementType::IE_UPLINK_DATA_STATUS,
        InformationElementType::IE_PDU_SESSION_STATUS,
        InformationElementType::IE_ALLOWED_PDU_SESSION_STATUS,
        InformationElementType::IE_NAS_MESSAGE_CONTAINER,
			};
      break;
    case MessageType::SERVICE_REJECT:
      optionalIEs = {
        InformationElementType::IE_PDU_SESSION_STATUS,
        InformationElementType::IE_T3346_VALUE,
        InformationElementType::IE_EAP_MESSAGE,
			};
      break;
    case MessageType::SERVICE_ACCEPT:
      optionalIEs = {
        InformationElementType::IE_PDU_SESSION_STATUS,
        InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT,
        InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE,
        InformationElementType::IE_EAP_MESSAGE,
			};
      break;
    case MessageType::CONFIGURATION_UPDATE_COMMAND:
      optionalIEs = {
          InformationElementType::IE_CONFIGURATION_UPDATE_INDICATION,
          InformationElementType::IE_5G_GUTI,
          InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY_LIST,
          InformationElementType::IE_ALLOWED_NSSAI,
          InformationElementType::IE_SERVICE_AREA_LIST,
          InformationElementType::IE_FULL_NAME_OF_NETWORK,
          InformationElementType::IE_SHORT_NAME_OF_NETWORK,
          InformationElementType::IE_LOCAL_TIME_ZONE,
          InformationElementType::IE_UINVERSAL_TIME_AND_LOCAL_TIME_ZONE,
          InformationElementType::IE_DAYLIGHT_SAVING_TIME,
          InformationElementType::IE_LADN_INFORMATION,
          InformationElementType::IE_MICO_INDICATION,
          InformationElementType::IE_NETWORK_SLICING_INDICATION,
          InformationElementType::IE_CONFIGURED_NSSAI,
          InformationElementType::IE_REJECTED_NSSAI,
          InformationElementType::IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS,
          InformationElementType::IE_SMS_INDICATION,
      };
      break;
    case MessageType::CONFIGURATION_UPDATE_COMPLETE:
      optionalIEs = {

			};
      break;
    case MessageType::AUTHENTICATION_REQUEST:
      optionalIEs = {
          InformationElementType::IE_AUTHENTICATION_PARAMETER_RAND,
          InformationElementType::IE_AUTHENTICATION_PARAMETER_AUTN,
          InformationElementType::IE_EAP_MESSAGE,
      };
      break;
    case MessageType::AUTHENTICATION_RESPONSE:
      optionalIEs = {
          InformationElementType::IE_AUTHENTICATION_RESPONSE_PARAMETER,
          InformationElementType::IE_EAP_MESSAGE,
      };
      break;
    case MessageType::AUTHENTICATION_REJECT:
      optionalIEs = {
          InformationElementType::IE_EAP_MESSAGE,
			};
      break;
    case MessageType::AUTHENTICATION_FAILURE:
      optionalIEs = {
         InformationElementType::IE_AUTHENTICATION_FAILURE_PARAMETER,
			};
      break;
    case MessageType::AUTHENTICATION_RESULT:
      optionalIEs = {
         InformationElementType::IE_ABBA,
			};
      break;
    case MessageType::IDENTITY_REQUEST:
      optionalIEs = {

			};
      break;
    case MessageType::IDENTITY_RESPONSE:
      optionalIEs = {

			};
      break;
    case MessageType::SECURITY_MODE_COMMAND:
      optionalIEs = {
          InformationElementType::IE_IMEISV_REQUEST,
          InformationElementType::IE_SELECTED_EPS_NAS_SECURITY_ALGORITHMS,
          InformationElementType::IE_ADDITIONAL_5G_SECURITY_INFORMATION,
          InformationElementType::IE_EAP_MESSAGE,
          InformationElementType::IE_ABBA,
          InformationElementType::IE_REPLAYED_S1_UE_SECURITY_CAPABILITY,
      };
      break;
    case MessageType::SECURITY_MODE_COMPLETE:
      optionalIEs = {
          InformationElementType::IE_IMEISV,
          InformationElementType::IE_NAS_MESSAGE_CONTAINER,
      };
      break;
    case MessageType::SECURITY_MODE_REJECT:
      optionalIEs = {

			};
      break;
    case MessageType::FIVEG_MM_STATUS:
      optionalIEs = {

			};
      break;
    case MessageType::NOTIFICATION:
      optionalIEs = {

			};
      break;
    case MessageType::NOTIFICATION_RESPONSE:
      optionalIEs = {

			};
      break;
    case MessageType::UL_NAS_TRANSPORT:
      optionalIEs = {
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_OLD_PDU_SESSION_ID,
          InformationElementType::IE_REQUEST_TYPE,
          InformationElementType::IE_S_NSSAI,
          InformationElementType::IE_DNN,
          InformationElementType::IE_ADDITIONAL_INFORMATION,         
      };
      break;
    case MessageType::DL_NAS_TRANSPORT:
      optionalIEs = {
          InformationElementType::IE_PDU_SESSION_ID,
          InformationElementType::IE_ADDITIONAL_INFORMATION,
          InformationElementType::IE_5GMM_CAUSE,
          InformationElementType::IE_BACK_OFF_TIMER_VALUE,
      };
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_REQUEST:
      optionalIEs = {
          InformationElementType::IE_PDU_SESSION_TYPE,
          InformationElementType::IE_SSC_MODE,
          InformationElementType::IE_5GSM_CAPABILITY,
          InformationElementType::IE_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS,
          InformationElementType::IE_ALWAYS_ON_PDU_SESSION_REQUESTED,        
          InformationElementType::IE_SM_PDU_DN_REQUEST_CONTAINER,
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS,    
      };
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT:
      optionalIEs = {
          InformationElementType::IE_5GSM_CAUSE,
          InformationElementType::IE_PDU_ADDRESS,
          InformationElementType::IE_RQ_TIMER_VALUE,
          InformationElementType::IE_S_NSSAI,
          InformationElementType::IE_ALWAYS_ON_PDU_SESSION_INDICATION,        
          InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS,
          InformationElementType::IE_EAP_MESSAGE,
          InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS,
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 
          InformationElementType::IE_DNN,
      };
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_REJECT:
      optionalIEs = {
          InformationElementType::IE_BACK_OFF_TIMER_VALUE,        
          InformationElementType::IE_ALLOWED_SSC_MODE,
          InformationElementType::IE_EAP_MESSAGE,
          InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR,
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 
			};
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_COMMAND:
      optionalIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS,
			};
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_COMPLETE:
      optionalIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS,
			};
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_RESULT:
      optionalIEs = {
          InformationElementType::IE_EAP_MESSAGE,
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS,
			};
      break;
    case MessageType::PDU_SESSION_MODIFICATION_REQUEST:
      optionalIEs = {
          InformationElementType::IE_5GSM_CAPABILITY,
          InformationElementType::IE_5GSM_CAUSE,
          InformationElementType::IE_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS,
          InformationElementType::IE_ALWAYS_ON_PDU_SESSION_REQUESTED,
          InformationElementType::IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE,        
          InformationElementType::IE_REQUESTED_QOS_RULES,
          InformationElementType::IE_REQUESTED_QOS_FLOW_DESCRIPTIONS,
          InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS,
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS,  
			};
      break;
    case MessageType::PDU_SESSION_MODIFICATION_REJECT:
      optionalIEs = {
          InformationElementType::IE_BACK_OFF_TIMER_VALUE,
          InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR,
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS,
			};
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMMAND:
      optionalIEs = {
          InformationElementType::IE_5GSM_CAUSE,
          InformationElementType::IE_SESSION_AMBR,
          InformationElementType::IE_RQ_TIMER_VALUE,
          InformationElementType::IE_ALWAYS_ON_PDU_SESSION_INDICATION,        
          InformationElementType::IE_AUTHORIZED_QOS_RULES,
          InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS,
          InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS,
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 
			};
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMPLETE:
      optionalIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 
			};
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMMAND_REJECT:
      optionalIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 
			};
      break;
    case MessageType::PDU_SESSION_RELEASE_REQUEST:
      optionalIEs = {
          InformationElementType::IE_5GMM_CAUSE, 
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 
			};
      break;
    case MessageType::PDU_SESSION_RELEASE_REJECT:
      optionalIEs = {
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 
			};
      break;
    case MessageType::PDU_SESSION_RELEASE_COMMAND:
      optionalIEs = {
          InformationElementType::IE_BACK_OFF_TIMER_VALUE,        
          InformationElementType::IE_EAP_MESSAGE,
          InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR,
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS,
			};
      break;
    case MessageType::PDU_SESSION_RELEASE_COMPLETE:
      optionalIEs = {
          InformationElementType::IE_5GMM_CAUSE, 
          InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 
			};
      break;
    case MessageType::FIVEG_SM_STATUS:
      optionalIEs = {

			};
      break;
    default:
      break;
    }
  }
  static uint32_t getNasMessageMinLength(MessageType msgtype) {
    MessageMinLen minLen = MessageMinLen::UNKNOWN;

    switch (msgtype) {
    case MessageType::REGISTRATION_REQUEST:
      minLen = MessageMinLen::REGISTRATION_REQUEST;
      break;
    case MessageType::REGISTRATION_ACCEPT:
      minLen = MessageMinLen::REGISTRATION_ACCEPT;
      break;
    case MessageType::REGISTRATION_COMPLETE:
      minLen = MessageMinLen::REGISTRATION_COMPLETE;
      break;
    case MessageType::REGISTRATION_REJECT:
      minLen = MessageMinLen::REGISTRATION_REJECT;
      break;
    case MessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING:
      minLen = MessageMinLen::DEREGISTRATION_REQUEST_UE_ORIGINATING;
      break;
    case MessageType::DEREGISTRATION_ACCEPT_UE_ORIGINATING:
      minLen = MessageMinLen::DEREGISTRATION_ACCEPT_UE_ORIGINATING;
      break;
    case MessageType::DEREGISTRATION_REQUEST_UE_TERMINATED:
      minLen = MessageMinLen::DEREGISTRATION_REQUEST_UE_TERMINATED;
      break;
    case MessageType::DEREGISTRATION_ACCEPT_UE_TERMINATED:
      minLen = MessageMinLen::DEREGISTRATION_ACCEPT_UE_TERMINATED;
      break;
    case MessageType::SERVICE_REQUEST:
      minLen = MessageMinLen::SERVICE_REQUEST;
      break;
    case MessageType::SERVICE_REJECT:
      minLen = MessageMinLen::SERVICE_REJECT;
      break;
    case MessageType::SERVICE_ACCEPT:
      minLen = MessageMinLen::SERVICE_ACCEPT;
      break;
    case MessageType::CONFIGURATION_UPDATE_COMMAND:
      minLen = MessageMinLen::CONFIGURATION_UPDATE_COMMAND;
      break;
    case MessageType::CONFIGURATION_UPDATE_COMPLETE:
      minLen = MessageMinLen::CONFIGURATION_UPDATE_COMPLETE;
      break;
    case MessageType::AUTHENTICATION_REQUEST:
      minLen = MessageMinLen::AUTHENTICATION_REQUEST;
      break;
    case MessageType::AUTHENTICATION_RESPONSE:
      minLen = MessageMinLen::AUTHENTICATION_RESPONSE;
      break;
    case MessageType::AUTHENTICATION_REJECT:
      minLen = MessageMinLen::AUTHENTICATION_REJECT;
      break;
    case MessageType::AUTHENTICATION_FAILURE:
      minLen = MessageMinLen::AUTHENTICATION_FAILURE;
      break;
    case MessageType::AUTHENTICATION_RESULT:
      minLen = MessageMinLen::AUTHENTICATION_RESULT;
      break;
    case MessageType::IDENTITY_REQUEST:
      minLen = MessageMinLen::IDENTITY_REQUEST;
      break;
    case MessageType::IDENTITY_RESPONSE:
      minLen = MessageMinLen::IDENTITY_RESPONSE;
      break;
    case MessageType::SECURITY_MODE_COMMAND:
      minLen = MessageMinLen::SECURITY_MODE_COMMAND;
      break;
    case MessageType::SECURITY_MODE_COMPLETE:
      minLen = MessageMinLen::SECURITY_MODE_COMPLETE;
      break;
    case MessageType::SECURITY_MODE_REJECT:
      minLen = MessageMinLen::SECURITY_MODE_REJECT;
      break;
    case MessageType::FIVEG_MM_STATUS:
      minLen = MessageMinLen::FIVEG_MM_STATUS;
      break;
    case MessageType::NOTIFICATION:
      minLen = MessageMinLen::NOTIFICATION;
      break;
    case MessageType::NOTIFICATION_RESPONSE:
      minLen = MessageMinLen::NOTIFICATION_RESPONSE;
      break;
    case MessageType::UL_NAS_TRANSPORT:
      minLen = MessageMinLen::UL_NAS_TRANSPORT;
      break;
    case MessageType::DL_NAS_TRANSPORT:
      minLen = MessageMinLen::DL_NAS_TRANSPORT;
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_REQUEST:
      minLen = MessageMinLen::PDU_SESSION_ESTABLISHMENT_REQUEST;
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT:
      minLen = MessageMinLen::PDU_SESSION_ESTABLISHMENT_ACCEPT;
      break;
    case MessageType::PDU_SESSION_ESTABLISHMENT_REJECT:
      minLen = MessageMinLen::PDU_SESSION_ESTABLISHMENT_REJECT;
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_COMMAND:
      minLen = MessageMinLen::PDU_SESSION_AUTHENTICATION_COMMAND;
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_COMPLETE:
      minLen = MessageMinLen::PDU_SESSION_AUTHENTICATION_COMPLETE;
      break;
    case MessageType::PDU_SESSION_AUTHENTICATION_RESULT:
      minLen = MessageMinLen::PDU_SESSION_AUTHENTICATION_RESULT;
      break;
    case MessageType::PDU_SESSION_MODIFICATION_REQUEST:
      minLen = MessageMinLen::PDU_SESSION_MODIFICATION_REQUEST;
      break;
    case MessageType::PDU_SESSION_MODIFICATION_REJECT:
      minLen = MessageMinLen::PDU_SESSION_MODIFICATION_REJECT;
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMMAND:
      minLen = MessageMinLen::PDU_SESSION_MODIFICATION_COMMAND;
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMPLETE:
      minLen = MessageMinLen::PDU_SESSION_MODIFICATION_COMPLETE;
      break;
    case MessageType::PDU_SESSION_MODIFICATION_COMMAND_REJECT:
      minLen = MessageMinLen::PDU_SESSION_MODIFICATION_COMMAND_REJECT;
      break;
    case MessageType::PDU_SESSION_RELEASE_REQUEST:
      minLen = MessageMinLen::PDU_SESSION_RELEASE_REQUEST;
      break;
    case MessageType::PDU_SESSION_RELEASE_REJECT:
      minLen = MessageMinLen::PDU_SESSION_RELEASE_REJECT;
      break;
    case MessageType::PDU_SESSION_RELEASE_COMMAND:
      minLen = MessageMinLen::PDU_SESSION_RELEASE_COMMAND;
      break;
    case MessageType::PDU_SESSION_RELEASE_COMPLETE:
      minLen = MessageMinLen::PDU_SESSION_RELEASE_COMPLETE;
      break;
    case MessageType::FIVEG_SM_STATUS:
      minLen = MessageMinLen::FIVEG_SM_STATUS;
      break;
    default:
      break;
    }
    return static_cast<uint32_t>(minLen);
  }

}; // NasUtils
/*
  InformationElementType::IE_NAS_KEY_SET_IDENTIFIER, 0x
  InformationElementType::IE_SECURITY_HEADER_TYPE, 0x
  InformationElementType::IE_SPARE_HALF_OCTET, 0x
  InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY, 0x
  InformationElementType::IE_MESSAGE_TYPE, 0x
  InformationElementType::IE_MESSAGE_AUTHENTICATION_CODE, 0x
  InformationElementType::IE_SEQUENCE_NUMBER, 0x
  InformationElementType::IE_ACCESS_TYPE, 0x
  InformationElementType::IE_GPRS_TIMER, 0x
  InformationElementType::IE_GPRS_TIMER_2, 0x
  InformationElementType::IE_GPRS_TIMER_3, 0x
  InformationElementType::IE_INTRA_N1_MODE_NAS_TRANSPARENT_CONTAINER, 0x
  InformationElementType::IE_N1_MODE_TO_S1_MODE_NAS_TRANSPARENT_CONTAINER, 0x
  InformationElementType::IE_S1_MODE_TO_N1_MODE_NAS_TRANSPARENT_CONTAINER, 0x
  InformationElementType::IE_5GS_DRX_PARAMETERS, 0x
  InformationElementType::IE_5GS_IDENTITY_TYPE, 0x
  InformationElementType::IE_5GS_MOBILE_IDENTITY, 0x
  InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT, 0x
  InformationElementType::IE_5GS_REGISTRATION_RESULT, 0x
  InformationElementType::IE_5GS_REGISTRATION_TYPE, 0x
  InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY, 0x
  InformationElementType::IE_ADDITIONAL_INFORMATION_REQUESTED, 0x
  InformationElementType::IE_CAG_INFORMATION_LIST, 0x
  InformationElementType::IE_CIOT_SMALL_DATA_CONTAINER, 0x
  InformationElementType::IE_CIPHERING_KEY_DATA, 0x
  InformationElementType::IE_CONTROL_PLANE_SERVICE_TYPE, 0x
  InformationElementType::IE_DAYLIGHT_SAVING_TIME, 0x
  InformationElementType::IE_DEREGISTRATION_TYPE, 0x
  InformationElementType::IE_EPS_NAS_SECURITY_ALGORITHMS, 0x
  InformationElementType::IE_EXTENDED_DRX_PARAMETERS, 0x
  InformationElementType::IE_MA_PDU_SESSION_INFORMATION, 0x
  InformationElementType::IE_MAPPED_NSSAI, 0x
  InformationElementType::IE_MOBILE_STATION_CLASSMARK_2, 0x
  InformationElementType::IE_NAS_KEY_SET_IDENTIFIER_1, 0x
  InformationElementType::IE_NAS_SECURITY_ALGORITHMS, 0x
  InformationElementType::IE_NETWORK_NAME, 0x
  InformationElementType::IE_NSSAI, 0x
  InformationElementType::IE_PDU_SESSION_IDENTITY_2, 0x
  InformationElementType::IE_PLMN_LIST, 0x
  InformationElementType::IE_RELEASE_ASSISTANCE_INDICATION, 0x
  InformationElementType::IE_S1_UE_SECURITY_CAPABILITY, 0x
  InformationElementType::IE_SERVICE_TYPE, 0x
  InformationElementType::IE_SUPPORTED_CODEC_LIST, 0x
  InformationElementType::IE_TIME_ZONE, 0x
  InformationElementType::IE_TIME_ZONE_AND_TIME, 0x
  InformationElementType::IE_UE_PARAMETERS_UPDATE_TRANSPARENT_CONTAINER, 0x
  InformationElementType::IE_UE_RADIO_CAPABILITY_ID, 0x
  InformationElementType::IE_UE_RADIO_CAPABILITY_ID_DELETION_INDICATION, 0x
  InformationElementType::IE_TRUNCATED_5G_S_TMSI_CONFIGURATION, 0x
  InformationElementType::IE_WUS_ASSISTANCE_INFORMATION, 0x
  InformationElementType::IE_N5GC_INDICATION, 0x
  InformationElementType::IE_NB_N1_MODE_DRX_PARAMETERS, 0x
  InformationElementType::IE_ADDITIONAL_CONFIGURATION_INDICATION, 0x
  InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 0x
  InformationElementType::IE_QOS_FLOW_DESCRIPTIONS, 0x
  InformationElementType::IE_QOS_RULES, 0x
  InformationElementType::IE_RE_ATTEMPT_INDICATOR, 0x
  InformationElementType::IE_SERVING_PLMN_RATE_CONTROL, 0x
  InformationElementType::IE_ATSSS_CONTAINER, 0x
  InformationElementType::IE_CONTROL_PLANE_ONLY_INDICATION, 0x
  InformationElementType::IE_IP_HEADER_COMPRESSION_CONFIGURATION, 0x
  InformationElementType::IE_DS_TT_ETHERNET_PORT_MAC_ADDRESS, 0x
  InformationElementType::IE_UE_DS_TT_RESIDENCE_TIME, 0x
  InformationElementType::IE_PORT_MANAGEMENT_INFORMATION_CONTAINER, 0x
  InformationElementType::IE_ETHERNET_HEADER_COMPRESSION_CONFIGURATION, 0x
*/

const std::unordered_map<InformationElementType, uint8_t>  OptionalIEValues = {
  { InformationElementType::IE_UNSUPPORTED, 0x00 },
  { InformationElementType::IE_NON_CURRENT_NATIVE_NAS_KEY_SET_IDENTIFIER, 0x0C },
  { InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, 0x7b },
  { InformationElementType::IE_PDU_SESSION_ID, 0x12 },
  { InformationElementType::IE_ADDITIONAL_INFORMATION, 0x24 },
  { InformationElementType::IE_DNN, 0x25 },
  { InformationElementType::IE_EAP_MESSAGE, 0x78 },
  { InformationElementType::IE_RQ_TIMER_VALUE, 0x56 },
  { InformationElementType::IE_NON_3GPP_DEREGISTRATION_TIMER_VAL, 0x5d },
  { InformationElementType::IE_T3502_VALUE, 0x16 },
  { InformationElementType::IE_BACK_OFF_TIMER_VALUE, 0x37 },
  { InformationElementType::IE_T3512_VALUE, 0x5e },
  { InformationElementType::IE_T3346_VALUE, 0x5f },
  { InformationElementType::IE_S_NSSAI, 0x22 },
  { InformationElementType::IE_5GMM_CAPABILITY, 0x10 },
  { InformationElementType::IE_5GMM_CAUSE, 0x58 },
  { InformationElementType::IE_REQUESTED_DRX_PARAMETERS, 0x51 },
  { InformationElementType::IE_NEGOTIATED_DRX_PARAMETERS, 0x51 },
  { InformationElementType::IE_5G_GUTI, 0x77 },
  { InformationElementType::IE_IMEISV, 0x77 },
  { InformationElementType::IE_ADDITIONAL_GUTI, 0x77 },
  { InformationElementType::IE_LAST_VISITED_REGISTERED_TRACKING_AREA_IDENTITY, 0x52 },
  { InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY_LIST, 0x54 },
  { InformationElementType::IE_5GS_UPDATE_TYPE, 0x53 },
  { InformationElementType::IE_ABBA, 0x38 },
  { InformationElementType::IE_ADDITIONAL_5G_SECURITY_INFORMATION, 0x36 },
  { InformationElementType::IE_ALLOWED_PDU_SESSION_STATUS, 0x25 },
  { InformationElementType::IE_AUTHENTICATION_FAILURE_PARAMETER, 0x30 },
  { InformationElementType::IE_AUTHENTICATION_PARAMETER_AUTN, 0x20 },
  { InformationElementType::IE_AUTHENTICATION_PARAMETER_RAND, 0x21 },
  { InformationElementType::IE_AUTHENTICATION_RESPONSE_PARAMETER, 0x2d },
  { InformationElementType::IE_CONFIGURATION_UPDATE_INDICATION, 0xd },
  { InformationElementType::IE_NETWORK_DAYLIGHT_SAVING_TIME, 0x49 },
  { InformationElementType::IE_EMERGENCY_NUMBER_LIST, 0x34 },
  { InformationElementType::IE_EPS_BEARER_CONTEXT_STATUS, 0x60 },
  { InformationElementType::IE_EPS_NAS_MESSAGE_CONTAINER, 0x70 },
  { InformationElementType::IE_SELECTED_EPS_NAS_SECURITY_ALGORITHMS, 0x57 },
  { InformationElementType::IE_EXTENDED_EMERGENCY_NUMBER_LIST, 0x7a },
  { InformationElementType::IE_IMEISV_REQUEST, 0xe },
  { InformationElementType::IE_LADN_INDICATION, 0x74 },
  { InformationElementType::IE_LADN_INFORMATION, 0x79 },
  { InformationElementType::IE_MICO_INDICATION, 0x0b },
  { InformationElementType::IE_NAS_MESSAGE_CONTAINER, 0x71 },
  { InformationElementType::IE_FULL_NAME_OF_NETWORK, 0x43 },
  { InformationElementType::IE_SHORT_NAME_OF_NETWORK, 0x45 },
  { InformationElementType::IE_NETWORK_SLICING_INDICATION, 0x09 },
  { InformationElementType::IE_NON_3GPP_NW_PROVIDED_POLICIES, 0x0d },
  { InformationElementType::IE_NSSAI_INCLUSION_MODE, 0xa },
  { InformationElementType::IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS, 0x76 },
  { InformationElementType::IE_PAYLOAD_CONTAINER, 0x7b },
  { InformationElementType::IE_PAYLOAD_CONTAINER_TYPE, 0x08 },
  { InformationElementType::IE_OLD_PDU_SESSION_ID, 0x59 },
  { InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT, 0x26 },
  { InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE, 0x72 },
  { InformationElementType::IE_PDU_SESSION_STATUS, 0x50 },
  { InformationElementType::IE_EQUIVALENT_PLMN_LIST, 0x4a },
  { InformationElementType::IE_REJECTED_NSSAI, 0x11 },
  { InformationElementType::IE_REQUESTED_NSSAI, 0x2f },
  { InformationElementType::IE_ALLOWED_NSSAI, 0x15 },
  { InformationElementType::IE_CONFIGURED_NSSAI, 0x31 },
  { InformationElementType::IE_REQUEST_TYPE, 0x08 },
  { InformationElementType::IE_S1_UE_NETWORK_CAPABILITY, 0x17 },
  { InformationElementType::IE_REPLAYED_S1_UE_SECURITY_CAPABILITY, 0x19 },
  { InformationElementType::IE_SERVICE_AREA_LIST, 0x27 },
  { InformationElementType::IE_SMS_INDICATION, 0xf },
  { InformationElementType::IE_SOR_TRANSPARENT_CONTAINER, 0x73 },
  { InformationElementType::IE_LOCAL_TIME_ZONE, 0x46 },
  { InformationElementType::IE_UINVERSAL_TIME_AND_LOCAL_TIME_ZONE, 0x47 },
  { InformationElementType::IE_UE_SECURITY_CAPABILITY, 0x2e },
  { InformationElementType::IE_UE_USAGE_SETTING, 0x18 },
  { InformationElementType::IE_UE_STATUS, 0x2b },
  { InformationElementType::IE_UPLINK_DATA_STATUS, 0x40 },
  { InformationElementType::IE_5GSM_CAPABILITY, 0x28 },
  { InformationElementType::IE_5GSM_CAUSE, 0x59 },
  { InformationElementType::IE_ALWAYS_ON_PDU_SESSION_INDICATION, 0x8 },
  { InformationElementType::IE_ALWAYS_ON_PDU_SESSION_REQUESTED, 0x0b },
  { InformationElementType::IE_ALLOWED_SSC_MODE, 0x0f },
  { InformationElementType::IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE, 0x13 },
  { InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS, 0x75 },
  { InformationElementType::IE_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS, 0x55 },
  { InformationElementType::IE_PDU_ADDRESS, 0x29 },
  { InformationElementType::IE_PDU_SESSION_TYPE, 0x09 },
  { InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS, 0x79 },
  { InformationElementType::IE_REQUESTED_QOS_FLOW_DESCRIPTIONS, 0x79 },
  { InformationElementType::IE_REQUESTED_QOS_RULES, 0x7a },
  { InformationElementType::IE_AUTHORIZED_QOS_RULES, 0x7a },
  { InformationElementType::IE_SESSION_AMBR, 0x2a },
  { InformationElementType::IE_SM_PDU_DN_REQUEST_CONTAINER, 0x39 },
  { InformationElementType::IE_SSC_MODE, 0x0a },
  { InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT, 0x21 },
  { InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR, 0x61 }
};

} // namespace nas
