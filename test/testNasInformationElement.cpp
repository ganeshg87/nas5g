#include <string>
#include "NasBuffer.h"
#include "NasInformationElement.h"
#include "NasUtils.h"


using namespace nas;

template <typename T>
bool validateInformationElement(std::string testcase, const std::string &hexBuf,
                                bool isOptional = false) {
  NasBuffer nasBuffer1(hexBuf);
  std::cout << "Before Decode : " << nasBuffer1.ToHexString() << std::endl;
  T ie;
  if (NasCause::NAS_CAUSE_SUCCESS != ie.Decode(nasBuffer1, isOptional)) {
    std::cout << testcase << " testcase failed.!" << std::endl;
    return false;
  }

  NasBuffer nasBuffer2;
  if (NasCause::NAS_CAUSE_SUCCESS != ie.Encode(nasBuffer2, isOptional)) {
    std::cout << testcase << " testcase failed.!" << std::endl;
    return false;
  }
  std::cout << "After Decode  : " << nasBuffer2.ToHexString() << std::endl;
  if (nasBuffer1.isEqual(nasBuffer2)) {
    std::cout << testcase << " testcase successfull." << std::endl;
    return true;
  }
  std::cout << testcase << " testcase failed.!" << std::endl;
  return false;
}



class NasInformationElementTest {
public:
struct TestCase {
  InformationElementType type;
  std::string hexString;
  bool isOptional;
};

std::vector<TestCase> m_testInformationElements;


bool execute() {
    bool status = true;
    for(auto& it: m_testInformationElements) {
        std::string s = NasUtils::Enum2String(it.type);
        status &= verify(it.type, s, it.hexString, it.isOptional);
    }
    return status;
}
bool verify(InformationElementType type, std::string testcase,
        const std::string &hexBuf, bool isOptional = false)    {
    
    if(hexBuf.empty()) {
      return true;
    }

    bool status = false;
    switch (type) {
      case InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR: {
        status = validateInformationElement<ExtendedProtocolDiscriminatorIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SECURITY_HEADER_TYPE: {
        status = validateInformationElement<SecurityHeaderTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PDU_SESSION_ID: {
        status = validateInformationElement<PduSessionIdIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SPARE_HALF_OCTET: {
        status = validateInformationElement<SpareHalfOctetIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY: {
        status = validateInformationElement<ProcedureTransactionIdentityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_MESSAGE_TYPE: {
        status = validateInformationElement<MessageTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_MESSAGE_AUTHENTICATION_CODE: {
        status = validateInformationElement<MessageAuthenticationCodeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SEQUENCE_NUMBER: {
        status = validateInformationElement<SequenceNumberIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ADDITIONAL_INFORMATION: {
        status = validateInformationElement<AdditionalInformationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ACCESS_TYPE: {
        status = validateInformationElement<AccessTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_DNN: {
        status = validateInformationElement<DnnIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_EAP_MESSAGE: {
        status = validateInformationElement<EapMessageIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_GPRS_TIMER: {
        status = validateInformationElement<GprsTimerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_GPRS_TIMER_2: {
        status = validateInformationElement<GprsTimer2IE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_GPRS_TIMER_3: {
        status = validateInformationElement<GprsTimer3IE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_INTRA_N1_MODE_NAS_TRANSPARENT_CONTAINER: {
        status = validateInformationElement<IntraN1ModeNasTransparentContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::
          IE_N1_MODE_TO_S1_MODE_NAS_TRANSPARENT_CONTAINER: {
        status = validateInformationElement<N1ModeToS1ModeNasTransparentContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_S_NSSAI: {
        status = validateInformationElement<SNssaiIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::
          IE_S1_MODE_TO_N1_MODE_NAS_TRANSPARENT_CONTAINER: {
        status = validateInformationElement<S1ModeToN1ModeNasTransparentContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GMM_CAPABILITY: {
        status = validateInformationElement<FiveGmmCapabilityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GMM_CAUSE: {
        status = validateInformationElement<FiveGmmCauseIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_DRX_PARAMETERS: {
        status = validateInformationElement<FiveGsDrxParametersIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_IDENTITY_TYPE: {
        status = validateInformationElement<FiveGsIdentityTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_MOBILE_IDENTITY: {
        status = validateInformationElement<MobileIdentityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT: {
        status = validateInformationElement<FiveGsNetworkFeatureSupportIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_REGISTRATION_RESULT: {
        status = validateInformationElement<FiveGsRegistrationResultIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_REGISTRATION_TYPE: {
        status = validateInformationElement<FiveGSRegistrationTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY: {
        status = validateInformationElement<FiveGsTrackingAreaIdentityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY_LIST: {
        status = validateInformationElement<FiveGsTrackingAreaIdentityListIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GS_UPDATE_TYPE: {
        status = validateInformationElement<FiveGsUpdateTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ABBA: {
        status = validateInformationElement<AbbaIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ADDITIONAL_5G_SECURITY_INFORMATION: {
        status = validateInformationElement<Additional5GSecurityInformationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ADDITIONAL_INFORMATION_REQUESTED: {
        status = validateInformationElement<AdditionalInformationRequestedIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ALLOWED_PDU_SESSION_STATUS: {
        status = validateInformationElement<AllowedPduSessionStatusIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_AUTHENTICATION_FAILURE_PARAMETER: {
        status = validateInformationElement<AuthenticationFailureParameterIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_AUTHENTICATION_PARAMETER_AUTN: {
        status = validateInformationElement<AuthenticationParameterAutnIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_AUTHENTICATION_PARAMETER_RAND: {
        status = validateInformationElement<AuthenticationParameterRandIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_AUTHENTICATION_RESPONSE_PARAMETER: {
        status = validateInformationElement<AuthenticationResponseParameterIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_CONFIGURATION_UPDATE_INDICATION: {
        status = validateInformationElement<ConfigurationUpdateIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_CAG_INFORMATION_LIST: {
        status = validateInformationElement<CagInformationListIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_CIOT_SMALL_DATA_CONTAINER: {
        status = validateInformationElement<CiotSmallDataContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_CIPHERING_KEY_DATA: {
        status = validateInformationElement<CipheringKeyDataIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_CONTROL_PLANE_SERVICE_TYPE: {
        status = validateInformationElement<ControlPlaneServiceTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_DAYLIGHT_SAVING_TIME: {
        status = validateInformationElement<DaylightSavingTimeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_DEREGISTRATION_TYPE: {
        status = validateInformationElement<DeRegistrationTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_EMERGENCY_NUMBER_LIST: {
        status = validateInformationElement<EmergencyNumberListIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_EPS_BEARER_CONTEXT_STATUS: {
        status = validateInformationElement<EpsBearerContextStatusIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_EPS_NAS_MESSAGE_CONTAINER: {
        status = validateInformationElement<EpsNasMessageContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_EPS_NAS_SECURITY_ALGORITHMS: {
        status = validateInformationElement<EpsNasSecurityAlgorithmsIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_EXTENDED_EMERGENCY_NUMBER_LIST: {
        status = validateInformationElement<ExtendedEmergencyNumberListIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_EXTENDED_DRX_PARAMETERS: {
        status = validateInformationElement<ExtendedDrxParametersIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_IMEISV_REQUEST: {
        status = validateInformationElement<ImeisvRequestIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_LADN_INDICATION: {
        status = validateInformationElement<LadnIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_LADN_INFORMATION: {
        status = validateInformationElement<LadnInformationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_MICO_INDICATION: {
        status = validateInformationElement<MicoIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_MA_PDU_SESSION_INFORMATION: {
        status = validateInformationElement<MaPduSessionInformationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_MAPPED_NSSAI: {
        status = validateInformationElement<MappedNssaiIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_MOBILE_STATION_CLASSMARK_2: {
        status = validateInformationElement<MobileStationClassmark2IE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NAS_KEY_SET_IDENTIFIER: {
        status = validateInformationElement<NasKeySetIdentifierIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NAS_MESSAGE_CONTAINER: {
        status = validateInformationElement<NasMessageContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NAS_SECURITY_ALGORITHMS: {
        status = validateInformationElement<NasSecurityAlgorithmsIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SELECTED_NAS_SECURITY_ALGORITHMS: {
        status = validateInformationElement<SelectedNasSecurityAlgorithmsIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NETWORK_NAME: {
        status = validateInformationElement<NetworkNameIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NETWORK_SLICING_INDICATION: {
        status = validateInformationElement<NetworkSlicingIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NON_3GPP_NW_PROVIDED_POLICIES: {
        status = validateInformationElement<Non3GppNwProvidedPoliciesIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NSSAI: {
        status = validateInformationElement<SNssaiIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NSSAI_INCLUSION_MODE: {
        status = validateInformationElement<NssaiInclusionModeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::
          IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS: {
        status = validateInformationElement<OperatorDefinedAccessCategoryDefinitionsIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PAYLOAD_CONTAINER: {
        status = validateInformationElement<PayloadContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PAYLOAD_CONTAINER_TYPE: {
        status = validateInformationElement<PayloadContainerTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PDU_SESSION_IDENTITY_2: {
        status = validateInformationElement<PduSessionIdentity2IE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT: {
        status = validateInformationElement<PduSessionReactivationResultIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::
          IE_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE: {
        status = validateInformationElement<PduSessionReactivationResultErrorCauseIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PDU_SESSION_STATUS: {
        status = validateInformationElement<PduSessionStatusIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PLMN_LIST: {
        status = validateInformationElement<PlmnListIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_REJECTED_NSSAI: {
        status = validateInformationElement<RejectedNssaiIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_RELEASE_ASSISTANCE_INDICATION: {
        status = validateInformationElement<ReleaseAssistanceIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_REQUEST_TYPE: {
        status = validateInformationElement<RequestTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_S1_UE_NETWORK_CAPABILITY: {
        status = validateInformationElement<S1UeNetworkCapabilityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_S1_UE_SECURITY_CAPABILITY: {
        status = validateInformationElement<S1UeSecurityCapabilityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SERVICE_AREA_LIST: {
        status = validateInformationElement<ServiceAreaListIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SERVICE_TYPE: {
        status = validateInformationElement<ServiceTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SMS_INDICATION: {
        status = validateInformationElement<SmsIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SOR_TRANSPARENT_CONTAINER: {
        status = validateInformationElement<SorTransparentContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SUPPORTED_CODEC_LIST: {
        status = validateInformationElement<SupportedCodecListIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_TIME_ZONE: {
        status = validateInformationElement<TimeZoneIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_TIME_ZONE_AND_TIME: {
        status = validateInformationElement<TimeZoneAndTimeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::
          IE_UE_PARAMETERS_UPDATE_TRANSPARENT_CONTAINER: {
        status = validateInformationElement<UeParametersUpdateTransparentContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_UE_SECURITY_CAPABILITY: {
        status = validateInformationElement<UeSecurityCapabilityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_REPLAYED_UE_SECURITY_CAPABILITY: {
        status = validateInformationElement<ReplayedUeSecurityCapabilityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_UE_USAGE_SETTING: {
        status = validateInformationElement<UeUsageSettingIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_UE_STATUS: {
        status = validateInformationElement<UeStatusIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_UPLINK_DATA_STATUS: {
        status = validateInformationElement<UplinkDataStatusIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_UE_RADIO_CAPABILITY_ID: {
        status = validateInformationElement<UeRadioCapabilityIdIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::
          IE_UE_RADIO_CAPABILITY_ID_DELETION_INDICATION: {
        status = validateInformationElement<UeRadioCapabilityIdDeletionIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_TRUNCATED_5G_S_TMSI_CONFIGURATION: {
        status = validateInformationElement<Truncated5GSTmsiConfigurationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_WUS_ASSISTANCE_INFORMATION: {
        status = validateInformationElement<WusAssistanceInformationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_N5GC_INDICATION: {
        status = validateInformationElement<N5GcIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_NB_N1_MODE_DRX_PARAMETERS: {
        status = validateInformationElement<NbN1ModeDrxParametersIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ADDITIONAL_CONFIGURATION_INDICATION: {
        status = validateInformationElement<AdditionalConfigurationIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GSM_CAPABILITY: {
        status = validateInformationElement<FiveGsmCapabilityIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GSM_CAUSE: {
        status = validateInformationElement<FiveGsmCauseIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ALWAYS_ON_PDU_SESSION_INDICATION: {
        status = validateInformationElement<AlwaysOnPduSessionIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ALWAYS_ON_PDU_SESSION_REQUESTED: {
        status = validateInformationElement<AlwaysOnPduSessionRequestedIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ALLOWED_SSC_MODE: {
        status = validateInformationElement<AllowedSscModeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SELECTED_SSC_MODE: {
        status = validateInformationElement<SelectedSscModeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS: {
        status = validateInformationElement<ExtendedProtocolConfigurationOptionsIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE: {
        status = validateInformationElement<IntegrityProtectionMaximumDataRateIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS: {
        status = validateInformationElement<MappedEpsBearerContextsIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::
          IE_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS: {
        status = validateInformationElement<MaximumNumberOfSupportedPacketFiltersIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PDU_ADDRESS: {
        status = validateInformationElement<PduAddressIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PDU_SESSION_TYPE: {
        status = validateInformationElement<PduSessionTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SELECTED_PDU_SESSION_TYPE: {
        status = validateInformationElement<SelectedPduSessionTypeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_QOS_FLOW_DESCRIPTIONS: {
        status = validateInformationElement<QosFlowDescriptionsIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_QOS_RULES: {
        status = validateInformationElement<QosRulesIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SESSION_AMBR: {
        status = validateInformationElement<SessionAmbrIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SM_PDU_DN_REQUEST_CONTAINER: {
        status = validateInformationElement<SmPduDnRequestContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_SSC_MODE: {
        status = validateInformationElement<SscModeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_RE_ATTEMPT_INDICATOR: {
        status = validateInformationElement<ReAttemptIndicatorIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      // case InformationElementType::IE_5GSM_NETWORK_FEATURE_SUPPORT: {
      //   status = validateInformationElement<FiveGsmNetworkFeatureSupportIE>(testcase,  hexBuf,  isOptional);
      //   break;
      // }
      case InformationElementType::IE_SERVING_PLMN_RATE_CONTROL: {
        status = validateInformationElement<ServingPlmnRateControlIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR: {
        status = validateInformationElement<FiveGsmCongestionReAttemptIndicatorIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ATSSS_CONTAINER: {
        status = validateInformationElement<AtsssContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_CONTROL_PLANE_ONLY_INDICATION: {
        status = validateInformationElement<ControlPlaneOnlyIndicationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_IP_HEADER_COMPRESSION_CONFIGURATION: {
        status = validateInformationElement<IpHeaderCompressionConfigurationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_DS_TT_ETHERNET_PORT_MAC_ADDRESS: {
        status = validateInformationElement<DsTtEthernetPortMacAddressIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_UE_DS_TT_RESIDENCE_TIME: {
        status = validateInformationElement<UeDsTtResidenceTimeIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_PORT_MANAGEMENT_INFORMATION_CONTAINER: {
        status = validateInformationElement<PortManagementInformationContainerIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_ETHERNET_HEADER_COMPRESSION_CONFIGURATION: {
        status = validateInformationElement<EthernetHeaderCompressionConfigurationIE>(testcase,  hexBuf,  isOptional);
        break;
      }
      case InformationElementType::IE_LAST_VISITED_REGISTERED_TRACKING_AREA_IDENTITY: {
        status = validateInformationElement<LastVisitedRegisteredTaiIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_5G_GUTI: {
          status = validateInformationElement<FiveGGutiIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_ADDITIONAL_GUTI: {
          status = validateInformationElement<AdditionalGutiIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_ALLOWED_NSSAI: {
          status = validateInformationElement<AllowedNssaiIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS: {
          status = validateInformationElement<AuthorizedQosFlowDescriptionsIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_AUTHORIZED_QOS_RULES: {
          status = validateInformationElement<AuthorizedQosRulesIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_BACK_OFF_TIMER_VALUE: {
          status = validateInformationElement<BackOffTimerValueIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_CONFIGURED_NSSAI: {
          status = validateInformationElement<ConfiguredNssaiIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_EQUIVALENT_PLMN_LIST: {
          status = validateInformationElement<EquivalentPlmnsIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_FULL_NAME_OF_NETWORK: {
          status = validateInformationElement<FullNameOfNetworkIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_IMEISV: {
          status = validateInformationElement<ImeiSvIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_LOCAL_TIME_ZONE: {
          status = validateInformationElement<LocalTimeZoneIE>(testcase,  hexBuf,  isOptional);
      break;
      }
      case InformationElementType::IE_NAS_KEY_SET_IDENTIFIER_1: {
        status = validateInformationElement<NasKeySetIdentifierIE>(testcase,  hexBuf,  isOptional);
      break;
      }
      case InformationElementType::IE_NEGOTIATED_DRX_PARAMETERS: {
        status = validateInformationElement<NegotiatedDrxParametersIE>(testcase,  hexBuf,  isOptional);
      break;
      }
      case InformationElementType::IE_NETWORK_DAYLIGHT_SAVING_TIME: {
        status = validateInformationElement<NetworkDaylightSavingTimeIE>(testcase,  hexBuf,  isOptional);
      break;
      }
      case InformationElementType::IE_NON_3GPP_DEREGISTRATION_TIMER_VAL: {
        status = validateInformationElement<Non3GPPDeregistrationTimerValueIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_NON_CURRENT_NATIVE_NAS_KEY_SET_IDENTIFIER: {
          status = validateInformationElement<NonCurrentNativeNasKeySetIdentifierIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_OLD_PDU_SESSION_ID: {
          status = validateInformationElement<OldPduSessionIdIE>(testcase,  hexBuf,  isOptional);
      break;
      }
      case InformationElementType::IE_REPLAYED_S1_UE_SECURITY_CAPABILITY: {
        status = validateInformationElement<ReplayedS1UeSecurityCapabilityIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_REQUESTED_DRX_PARAMETERS: {
          status = validateInformationElement<RequestedDrxParametersIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_REQUESTED_NSSAI: {
          status = validateInformationElement<RequestedNssaiIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_REQUESTED_QOS_FLOW_DESCRIPTIONS: {
          status = validateInformationElement<RequestedQosFlowDescriptionsIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_REQUESTED_QOS_RULES: {
          status = validateInformationElement<RequestedQosRulesIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_RQ_TIMER_VALUE: {
          status = validateInformationElement<RQTimerValueIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_SELECTED_EPS_NAS_SECURITY_ALGORITHMS: {
          status = validateInformationElement<SelectedEpsNasSecurityAlgorithmsIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_SHORT_NAME_OF_NETWORK: {
          status = validateInformationElement<ShortNameOfNetworkIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_T3346_VALUE: {
          status = validateInformationElement<T3346ValueIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_T3502_VALUE: {
          status = validateInformationElement<T3502ValueIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_T3512_VALUE: {
          status = validateInformationElement<T3512ValueIE>(testcase,  hexBuf,  isOptional);
      break;
      }
        case InformationElementType::IE_UINVERSAL_TIME_AND_LOCAL_TIME_ZONE: {
          status = validateInformationElement<UniversalTimeAndLocalTimeZoneIE>(testcase,  hexBuf,  isOptional);
      break;
      }
      default: {
        break;
      }
    }
    return status;
  }

public:

  static bool TestAllNasInformationElements() {
    NasInformationElementTest ieTest;
    ieTest.setup();
    return ieTest.execute();
  }

  void setup() {
      m_testInformationElements = {
        { InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR, "7e", false },
        { InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR, "2e", false },
        { InformationElementType::IE_SECURITY_HEADER_TYPE, "02", false },
        { InformationElementType::IE_PDU_SESSION_ID, "01", false },
        { InformationElementType::IE_SPARE_HALF_OCTET, "00", false },
        { InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY, "01", false },
        { InformationElementType::IE_MESSAGE_TYPE, "42", false },
        { InformationElementType::IE_MESSAGE_AUTHENTICATION_CODE, "b7e0d4d6", false },
        { InformationElementType::IE_SEQUENCE_NUMBER, "01", false },
        { InformationElementType::IE_ADDITIONAL_INFORMATION, "", false },
        { InformationElementType::IE_ACCESS_TYPE, "", false },
        { InformationElementType::IE_DNN, "250908696e7465726e6574", true },
        { InformationElementType::IE_EAP_MESSAGE, "", false },
        { InformationElementType::IE_GPRS_TIMER, "", false },
        { InformationElementType::IE_GPRS_TIMER_2, "", false },
        { InformationElementType::IE_GPRS_TIMER_3, "5e0106", true },
        { InformationElementType::IE_INTRA_N1_MODE_NAS_TRANSPARENT_CONTAINER, "", false },
        { InformationElementType::IE_N1_MODE_TO_S1_MODE_NAS_TRANSPARENT_CONTAINER, "", false },
        { InformationElementType::IE_S_NSSAI, "220101", true },
        { InformationElementType::IE_S1_MODE_TO_N1_MODE_NAS_TRANSPARENT_CONTAINER, "", false },
        { InformationElementType::IE_5GMM_CAPABILITY, "100107", false },
        { InformationElementType::IE_5GMM_CAUSE, "47", false },
        { InformationElementType::IE_5GS_DRX_PARAMETERS, "", false },
        { InformationElementType::IE_5GS_IDENTITY_TYPE, "01", false },
        { InformationElementType::IE_5GS_MOBILE_IDENTITY, "77000bf200f110010040cd44e87a", false },
        { InformationElementType::IE_5GS_MOBILE_IDENTITY, "000d0100f110f0ff00000030000069", false },
        { InformationElementType::IE_5GS_MOBILE_IDENTITY, "7700093515245019363320f8", false },
        { InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT, "", false },
        { InformationElementType::IE_5GS_REGISTRATION_RESULT, "0101", false },
        { InformationElementType::IE_5GS_REGISTRATION_TYPE, "19", false },
        { InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY, "", false },
        { InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY_LIST, "54070000f110000001", false },
        { InformationElementType::IE_5GS_UPDATE_TYPE, "530101", false },
        { InformationElementType::IE_ABBA, "020000", false },
        { InformationElementType::IE_ADDITIONAL_5G_SECURITY_INFORMATION, "", false },
        { InformationElementType::IE_ADDITIONAL_INFORMATION_REQUESTED, "", false },
        { InformationElementType::IE_ALLOWED_PDU_SESSION_STATUS, "", false },
        { InformationElementType::IE_AUTHENTICATION_FAILURE_PARAMETER, "", false },
        { InformationElementType::IE_AUTHENTICATION_PARAMETER_AUTN, "2010cc1dce4acc7280001353d70d9b8f5ff4", true },
        { InformationElementType::IE_AUTHENTICATION_PARAMETER_RAND, "218fc5e76084110da2db95115467dc6cf1", true },
        { InformationElementType::IE_AUTHENTICATION_RESPONSE_PARAMETER, "2d10e11eeb5ac4ffc67c4c215d7a680d96ba", true },
        { InformationElementType::IE_CONFIGURATION_UPDATE_INDICATION, "", false },
        { InformationElementType::IE_CAG_INFORMATION_LIST, "", false },
        { InformationElementType::IE_CIOT_SMALL_DATA_CONTAINER, "", false },
        { InformationElementType::IE_CIPHERING_KEY_DATA, "", false },
        { InformationElementType::IE_CONTROL_PLANE_SERVICE_TYPE, "", false },
        { InformationElementType::IE_DAYLIGHT_SAVING_TIME, "", false },
        { InformationElementType::IE_DEREGISTRATION_TYPE, "01", false },
        { InformationElementType::IE_EMERGENCY_NUMBER_LIST, "", false },
        { InformationElementType::IE_EPS_BEARER_CONTEXT_STATUS, "", false },
        { InformationElementType::IE_EPS_NAS_MESSAGE_CONTAINER, "", false },
        { InformationElementType::IE_EPS_NAS_SECURITY_ALGORITHMS, "", false },
        { InformationElementType::IE_EXTENDED_EMERGENCY_NUMBER_LIST, "", false },
        { InformationElementType::IE_EXTENDED_DRX_PARAMETERS, "", false },
        { InformationElementType::IE_IMEISV_REQUEST, "e1", false },
        { InformationElementType::IE_LADN_INDICATION, "740000", false },
        { InformationElementType::IE_LADN_INFORMATION, "", false },
        { InformationElementType::IE_MICO_INDICATION, "", false },
        { InformationElementType::IE_MA_PDU_SESSION_INFORMATION, "", false },
        { InformationElementType::IE_MAPPED_NSSAI, "", false },
        { InformationElementType::IE_MOBILE_STATION_CLASSMARK_2, "", false },
        { InformationElementType::IE_NAS_KEY_SET_IDENTIFIER, "19", false },
        { InformationElementType::IE_NAS_MESSAGE_CONTAINER, "", false },
        { InformationElementType::IE_NAS_SECURITY_ALGORITHMS, "02", false },
        { InformationElementType::IE_SELECTED_NAS_SECURITY_ALGORITHMS, "", false },
        { InformationElementType::IE_NETWORK_NAME, "", false },
        { InformationElementType::IE_NETWORK_SLICING_INDICATION, "90", true },
        { InformationElementType::IE_NON_3GPP_NW_PROVIDED_POLICIES, "", false },
        { InformationElementType::IE_NSSAI, "", false },
        { InformationElementType::IE_NSSAI_INCLUSION_MODE, "", false },
        { InformationElementType::IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS, "", false },
        { InformationElementType::IE_PAYLOAD_CONTAINER, "00372e0101c211000901000631310101ff0906010004010003290501c0a8800c2201017b000880000d0408080808250908696e7465726e6574", false },
        { InformationElementType::IE_PAYLOAD_CONTAINER_TYPE, "01", false },
        { InformationElementType::IE_PDU_SESSION_IDENTITY_2, "1201", true },
        { InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT, "", false },
        { InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE, "", false },
        { InformationElementType::IE_PDU_SESSION_STATUS, "50022000", true },
        { InformationElementType::IE_PLMN_LIST, "", false },
        { InformationElementType::IE_REJECTED_NSSAI, "", false },
        { InformationElementType::IE_RELEASE_ASSISTANCE_INDICATION, "", false },
        { InformationElementType::IE_REQUEST_TYPE, "81", false },
        { InformationElementType::IE_S1_UE_NETWORK_CAPABILITY, "1707f0f00000188030", true },
        { InformationElementType::IE_S1_UE_SECURITY_CAPABILITY, "", false },
        { InformationElementType::IE_SERVICE_AREA_LIST, "27070064f000003039", true },
        { InformationElementType::IE_SERVICE_TYPE, "51", false },
        { InformationElementType::IE_SMS_INDICATION, "", false },
        { InformationElementType::IE_SOR_TRANSPARENT_CONTAINER, "", false },
        { InformationElementType::IE_SUPPORTED_CODEC_LIST, "", false },
        { InformationElementType::IE_TIME_ZONE, "", false },
        { InformationElementType::IE_TIME_ZONE_AND_TIME, "", false },
        { InformationElementType::IE_UE_PARAMETERS_UPDATE_TRANSPARENT_CONTAINER, "", false },
        { InformationElementType::IE_UE_SECURITY_CAPABILITY, "2e04f070f0f0", true },
        { InformationElementType::IE_REPLAYED_UE_SECURITY_CAPABILITY, "04f070f0f0", false },
        { InformationElementType::IE_UE_USAGE_SETTING, "180100", true },
        { InformationElementType::IE_UE_STATUS, "", false },
        { InformationElementType::IE_UPLINK_DATA_STATUS, "", false },
        { InformationElementType::IE_UE_RADIO_CAPABILITY_ID, "", false },
        { InformationElementType::IE_UE_RADIO_CAPABILITY_ID_DELETION_INDICATION, "", false },
        { InformationElementType::IE_TRUNCATED_5G_S_TMSI_CONFIGURATION, "", false },
        { InformationElementType::IE_WUS_ASSISTANCE_INFORMATION, "", false },
        { InformationElementType::IE_N5GC_INDICATION, "", false },
        { InformationElementType::IE_NB_N1_MODE_DRX_PARAMETERS, "", false },
        { InformationElementType::IE_ADDITIONAL_CONFIGURATION_INDICATION, "", false },
        { InformationElementType::IE_5GSM_CAPABILITY, "280100", true },
        { InformationElementType::IE_5GSM_CAUSE, "5932", true },
        { InformationElementType::IE_ALWAYS_ON_PDU_SESSION_INDICATION, "", false },
        { InformationElementType::IE_ALWAYS_ON_PDU_SESSION_REQUESTED, "", false },
        { InformationElementType::IE_ALLOWED_SSC_MODE, "", false },
        { InformationElementType::IE_SELECTED_SSC_MODE, "", false },
        { InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, "7b000880000d0408080808", true },
        { InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, "7b000f80000d0408080808000d0408080404", true },
        { InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS, "7b00388080211001000010810600000000830600000000000d00000300000100000c00001200000200000a00000500001000001100002300002400", true },
        { InformationElementType::IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE, "", false },
        { InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS, "75001760001452010905fefeffff404a00000406fefefafaf6f6", true },
        { InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS, "75002960000cf20406fefefafa02020101057000175201050187878787030d2130fe091002010102ffffffff", true },
        { InformationElementType::IE_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS, "", false },
        { InformationElementType::IE_PDU_ADDRESS, "290501c0a8800c", true },
        { InformationElementType::IE_PDU_SESSION_TYPE, "11", false },
        { InformationElementType::IE_SELECTED_PDU_SESSION_TYPE, "", false },
        { InformationElementType::IE_QOS_FLOW_DESCRIPTIONS, "", false },
        { InformationElementType::IE_QOS_RULES, "", false },
        { InformationElementType::IE_SESSION_AMBR, "06010004010003", false },
        { InformationElementType::IE_SESSION_AMBR, "2a060601f40601f4", true },
        { InformationElementType::IE_SM_PDU_DN_REQUEST_CONTAINER, "", false },
        { InformationElementType::IE_SSC_MODE, "", false },
        { InformationElementType::IE_RE_ATTEMPT_INDICATOR, "", false },
        { InformationElementType::IE_SERVING_PLMN_RATE_CONTROL, "", false },
        { InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR, "", false },
        { InformationElementType::IE_ATSSS_CONTAINER, "", false },
        { InformationElementType::IE_CONTROL_PLANE_ONLY_INDICATION, "", false },
        { InformationElementType::IE_IP_HEADER_COMPRESSION_CONFIGURATION, "", false },
        { InformationElementType::IE_DS_TT_ETHERNET_PORT_MAC_ADDRESS, "", false },
        { InformationElementType::IE_UE_DS_TT_RESIDENCE_TIME, "", false },
        { InformationElementType::IE_PORT_MANAGEMENT_INFORMATION_CONTAINER, "", false },
        { InformationElementType::IE_ETHERNET_HEADER_COMPRESSION_CONFIGURATION, "", false },
        { InformationElementType::IE_LAST_VISITED_REGISTERED_TRACKING_AREA_IDENTITY, "5200f110000001", true },
        { InformationElementType::IE_5G_GUTI, "", false },
        { InformationElementType::IE_ADDITIONAL_GUTI, "", false },
        { InformationElementType::IE_ALLOWED_NSSAI, "15020101", false },
        { InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS, "790006012041010109", true },
        { InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS, "790009052042010105070160", true },
        { InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS, "7900260560420701600101050120460701700101010203011388030301138804030113880503011388", true },
        { InformationElementType::IE_AUTHORIZED_QOS_RULES, "000905000631300101fe05", false },
        { InformationElementType::IE_AUTHORIZED_QOS_RULES, "7a001a05000691300101fe0501000e2130091002010102ffffffff0101", true },
        { InformationElementType::IE_BACK_OFF_TIMER_VALUE, "", false },
        { InformationElementType::IE_CONFIGURED_NSSAI, "", false },
        { InformationElementType::IE_EQUIVALENT_PLMN_LIST, "", false },
        { InformationElementType::IE_FULL_NAME_OF_NETWORK, "", false },
        { InformationElementType::IE_IMEISV, "", false },
        { InformationElementType::IE_LOCAL_TIME_ZONE, "", false },
        { InformationElementType::IE_NAS_KEY_SET_IDENTIFIER_1, "", false },
        { InformationElementType::IE_NEGOTIATED_DRX_PARAMETERS, "510101", true },
        { InformationElementType::IE_NETWORK_DAYLIGHT_SAVING_TIME, "", false },
        { InformationElementType::IE_NON_3GPP_DEREGISTRATION_TIMER_VAL, "", false },
        { InformationElementType::IE_NON_CURRENT_NATIVE_NAS_KEY_SET_IDENTIFIER, "", false },
        { InformationElementType::IE_OLD_PDU_SESSION_ID, "", false },
        { InformationElementType::IE_REPLAYED_S1_UE_SECURITY_CAPABILITY, "04f070f0f0", false },
        { InformationElementType::IE_REQUESTED_DRX_PARAMETERS, "", false },
        { InformationElementType::IE_REQUESTED_NSSAI, "2f020101", false },
        { InformationElementType::IE_REQUESTED_QOS_FLOW_DESCRIPTIONS, "", false },
        { InformationElementType::IE_REQUESTED_QOS_RULES, "", false },
        { InformationElementType::IE_RQ_TIMER_VALUE, "", false },
        { InformationElementType::IE_SELECTED_EPS_NAS_SECURITY_ALGORITHMS, "", false },
        { InformationElementType::IE_SHORT_NAME_OF_NETWORK, "", false },
        { InformationElementType::IE_T3346_VALUE, "", false },
        { InformationElementType::IE_T3502_VALUE, "", false },
        { InformationElementType::IE_T3512_VALUE, "", false },
        { InformationElementType::IE_UINVERSAL_TIME_AND_LOCAL_TIME_ZONE, "", false },
      };
  }
}; 

int main() {
  if (!NasInformationElementTest::TestAllNasInformationElements()) {
    std::cout << "Failed NasInformationElementTest..?\n";
  } else {
    std::cout << "All test cases Passed..!!!!\n";
  }
  return 0;
}