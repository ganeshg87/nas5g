#pragma once
// https://www.etsi.org/deliver/etsi_ts/124500_124599/124501/16.05.01_60/ts_124501v160501p.pdf
#include <unordered_map>
#include <unordered_set>

#include "NasInformationElement.h"
#include "NasUtils.h"

namespace nas {

//**************************Nas Messages *********************/

class NasSecurityInformationElementContainer {

  std::vector<std::shared_ptr<InformationElement>> m_security;

public:
  ~NasSecurityInformationElementContainer() {
    m_security.clear();
  }

  NasCause Decode(const NasBuffer &nasBuffer) {
    NasCause cause = NasCause::NAS_CAUSE_FAILURE;

    if(ExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES == 
              nasBuffer.GetExtendedProtocolDiscriminator()) {
        return NasCause::NAS_CAUSE_SUCCESS;
    }
    
    if (SecurityHeaderType::NOT_PROTECTED ==
        nasBuffer.GetSecurityHeaderType()) {
      return NasCause::NAS_CAUSE_SUCCESS;
    }

    std::vector<InformationElementType> securityIETypes;
    NasUtils::GetSupportedSecurityIEs(securityIETypes);

    if (securityIETypes.empty()) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    for (auto ieType : securityIETypes) {
      std::shared_ptr<InformationElement> pIEI =
          InformationElementFactory::AllocInformationElement(ieType);

      if (!pIEI) {
        return NasCause::NAS_CAUSE_FAILURE;
      }

      cause = pIEI->Decode(nasBuffer);

      if (cause != NasCause::NAS_CAUSE_SUCCESS) {
        return cause;
      }
      m_security.emplace_back(pIEI);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer) const {
    NasCause cause = NasCause::NAS_CAUSE_FAILURE;

    if(m_security.empty()) {
      return NasCause::NAS_CAUSE_SUCCESS;
    }

    std::vector<InformationElementType> securityIETypes;
    NasUtils::GetSupportedSecurityIEs(securityIETypes);

    if (securityIETypes.empty()) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    auto it = m_security.begin();
    for (auto ieType : securityIETypes) {

      if (it == m_security.end()) {
        return NasCause::NAS_CAUSE_FAILURE;
      }

      if ((*it)->getInformationElementType() != ieType) {
        return NasCause::NAS_CAUSE_FAILURE;
      }
      cause = (*it)->Encode(nasBuffer);
      if (cause != NasCause::NAS_CAUSE_SUCCESS) {
        return cause;
      }
      ++it;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class NasMandatoryInformationElementContainer{
private:
  std::vector<std::shared_ptr<InformationElement>> m_mandatoryIEs;

  MessageType GetMessageType() const {
    if (!m_mandatoryIEs.empty() && m_mandatoryIEs.size() >= 4) {
      std::shared_ptr<MessageTypeIE> pIE = 
              std::dynamic_pointer_cast<MessageTypeIE>(m_mandatoryIEs[3]);
      if (pIE) {
        return pIE->GetMessageType();
      }
    }
    return MessageType::NOT_DEFINED;
  }

public:
  ~NasMandatoryInformationElementContainer() {
    m_mandatoryIEs.clear();
  }

  NasCause Decode(const NasBuffer &nasBuffer) {
    NasCause cause = NasCause::NAS_CAUSE_FAILURE;

    std::vector<InformationElementType> mandatoryIETypes;
    NasUtils::GetSupportedMandatoryIEs(nasBuffer.GetMessageType(),
                                       mandatoryIETypes);

    if (mandatoryIETypes.empty()) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    for (auto ieType : mandatoryIETypes) {
      std::shared_ptr<InformationElement> pIEI =
          InformationElementFactory::AllocInformationElement(ieType);
      if (!pIEI) {
        return NasCause::NAS_CAUSE_FAILURE;
      }

      cause = pIEI->Decode(nasBuffer);

      if (cause != NasCause::NAS_CAUSE_SUCCESS) {
        return cause;
      }
      m_mandatoryIEs.emplace_back(pIEI);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer) const {
    NasCause cause = NasCause::NAS_CAUSE_FAILURE;

    std::vector<InformationElementType> mandatoryIETypes;
    NasUtils::GetSupportedMandatoryIEs(GetMessageType(), mandatoryIETypes);

    if (mandatoryIETypes.empty()) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    auto it = m_mandatoryIEs.begin();
    for (auto ieType : mandatoryIETypes) {

      if (it == m_mandatoryIEs.end()) {
        return NasCause::NAS_CAUSE_FAILURE;
      }

      if ((*it)->getInformationElementType() != ieType) {
        return NasCause::NAS_CAUSE_FAILURE;
      }
      cause = (*it)->Encode(nasBuffer);
      if (cause != NasCause::NAS_CAUSE_SUCCESS) {
        return cause;
      }
      ++it;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class NasOptionalInformationElementContainer {
private:
  std::vector<std::shared_ptr<InformationElement>> m_optionalIEv;
  std::unordered_map<InformationElementType, std::shared_ptr<InformationElement>>
      m_optionalIEs;

  InformationElementType GetInformationElementType(uint8_t ieVal, 
            std::unordered_set<InformationElementType> &optionalIEs) const {
      InformationElementType type = InformationElementType::IE_UNSUPPORTED;

      for(auto& it: optionalIEs) {

          const auto& v = nas::OptionalIEValues.find(it);
          if(v == nas::OptionalIEValues.end()) {
            return InformationElementType::IE_UNSUPPORTED;
          }

          if(v->second == ieVal) {
              type = v->first;
              break;
          }
      }
      return type;
  }

public:
  ~NasOptionalInformationElementContainer() {
    m_optionalIEs.clear();
  }

  NasCause Decode(const NasBuffer &nasBuffer) {

    std::unordered_set<InformationElementType> supportedOptionalIEs;
    NasUtils::GetSupportedOptionalIEs(nasBuffer.GetMessageType(),
                                      supportedOptionalIEs);

    while (!nasBuffer.EndOfBuffer()) {

      uint8_t ieVal = nasBuffer.GetCurrentOctet();
      InformationElementType ieType =  GetInformationElementType(ieVal, supportedOptionalIEs);
      if(InformationElementType::IE_UNSUPPORTED == ieType) {
        ieType =  GetInformationElementType((ieVal & 0xF0) >> 4, supportedOptionalIEs);
      }

      if (InformationElementType::IE_UNSUPPORTED == ieType) {
          std::cout << ieVal
                    << " Optional IE does not supported" << std::endl;
          return NasCause::NAS_CAUSE_FAILURE;
      }

      std::shared_ptr<InformationElement> pIEI =
          InformationElementFactory::AllocInformationElement(ieType);

      if (!pIEI) {
        std::cout << NasUtils::Enum2String(ieType)
                  << " Optional IEI  not implemented" << std::endl;
        return NasCause::NAS_CAUSE_FAILURE;
      }

      if (pIEI->Decode(nasBuffer, true) == NasCause::NAS_CAUSE_FAILURE) {
        return NasCause::NAS_CAUSE_FAILURE;
      }

      m_optionalIEs.emplace(ieType, pIEI);
      m_optionalIEv.emplace_back(pIEI);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer) const {

   std::unordered_set<InformationElementType> supportedOptionalIEs;

    NasUtils::GetSupportedOptionalIEs(nasBuffer.GetMessageType(),
                                      supportedOptionalIEs);
    for (auto &iei : m_optionalIEv) {
     
      std::shared_ptr<InformationElement> pElement = iei;
      if (!pElement) {
        continue;
      }

      if (supportedOptionalIEs.end() == 
            supportedOptionalIEs.find(iei->getInformationElementType())) {
        continue;
      }

      if (pElement->Encode(nasBuffer, true) == NasCause::NAS_CAUSE_FAILURE) {
        return NasCause::NAS_CAUSE_FAILURE;
      }
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class Message {
  public:
    Message(){}
    ~Message(){}
};

class NasMessage : public Message {
  
  NasSecurityInformationElementContainer  m_security;
  NasMandatoryInformationElementContainer m_mandatory;
  NasOptionalInformationElementContainer  m_optional;


  NasCause validateNasMsgBoundary(MessageType msgtype,
                                  const NasBuffer &nasBuffer) {
    uint32_t minLen = 0;

#define MAX_NAS_MESSAGE_LENGTH 90000
    if (nasBuffer.Size() > MAX_NAS_MESSAGE_LENGTH) {
      return NasCause::NAS_MSG_TOO_LONG;
    }

    minLen = NasUtils::getNasMessageMinLength(msgtype);

    if (nasBuffer.Size() < minLen) {
      return NasCause::NAS_MSG_TOO_SHORT;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause validateMessageType(const NasBuffer &nasBuffer) {
    MessageType msgType = nasBuffer.GetMessageType();
    if ((msgType > MessageType::NOT_DEFINED) &&
        (msgType <= MessageType::FIVEG_SM_STATUS)) {
      return NasCause::NAS_CAUSE_SUCCESS;
    }
    return NasCause::NAS_MSG_TYPE_NOT_SUPPORTED;
  }

  NasCause validateEpd(const NasBuffer &nasBuffer) {
    ExtendedProtocolDiscriminator epd =
        nasBuffer.GetExtendedProtocolDiscriminator();
    if ((epd == ExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES) ||
        (epd == ExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES)) {
      return NasCause::NAS_CAUSE_SUCCESS;
    }
    return NasCause::NAS_EPD_NOT_SUPPORTED;
  }

public:
  NasMessage() {}
  ~NasMessage() {}

  std::string ToHexString() {
    NasBuffer nasBuffer;
    this->Encode(nasBuffer);
    return nasBuffer.ToHexString();
  }

  NasCause Decode(const NasBuffer &nasBuffer) {

    if (NasCause::NAS_CAUSE_FAILURE ==
        m_security.Decode(nasBuffer)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    if (NasCause::NAS_CAUSE_FAILURE ==
        m_mandatory.Decode(nasBuffer)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    if (NasCause::NAS_CAUSE_FAILURE ==
        m_optional.Decode(nasBuffer)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer) const {

    if (NasCause::NAS_CAUSE_FAILURE ==
        m_security.Encode(nasBuffer)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    if (NasCause::NAS_CAUSE_FAILURE ==
        m_mandatory.Encode(nasBuffer)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    if (NasCause::NAS_CAUSE_FAILURE ==
        m_optional.Encode(nasBuffer)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

} // namespace nas
