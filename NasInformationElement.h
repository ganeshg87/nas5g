#pragma once

#include <memory>
#include "NasBuffer.h"

namespace nas {

//**************************Information Elements *********************/

class InformationElement {

protected:
  bool DecodeIEType(const NasBuffer &nasBuffer, bool isNibble = false) {
 
    if (isNibble) {
      nasBuffer.DecodeNibble();
    } else {
      nasBuffer.DecodeU8();
    }

    return true;
  }

  bool EncodeIEType(NasBuffer &nasBuffer, bool isNibble = false) const {

    InformationElementType ieType = (getInformationElementType());
    const auto& it = OptionalIEValues.find(ieType);
    if(it == OptionalIEValues.end()) {
      return false;
    }

    uint8_t ieVal = it->second;

    if (isNibble) {
      nasBuffer.EncodeNibble(ieVal);
    } else {
      nasBuffer.EncodeU8(ieVal);
    }

    return true;
  }

public:
  virtual InformationElementType getInformationElementType() const {
    return InformationElementType::IE_UNSUPPORTED;
  }

  virtual size_t Size() const { return 0; }

  virtual NasCause Decode(const NasBuffer &nasBuffer, bool isOptional = false) {
    return NasCause::NAS_CAUSE_FAILURE;
  }

  virtual NasCause Encode(NasBuffer &nasBuffer, bool isOptional = false) const {
    return NasCause::NAS_CAUSE_FAILURE;
  }

  virtual ~InformationElement() {}
};

class ExtendedProtocolDiscriminatorIE : public InformationElement {

private:
  ExtendedProtocolDiscriminator m_extendedProtocolDiscriminator =
      ExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES;

public:
  ExtendedProtocolDiscriminatorIE() {}

  size_t Size() const override {
    return sizeof(m_extendedProtocolDiscriminator);
  }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR;
  }

  void SetExtendedProtocolDiscriminator(ExtendedProtocolDiscriminator epd) {
    m_extendedProtocolDiscriminator = epd;
  }
  ExtendedProtocolDiscriminator GetExtendedProtocolDiscriminator() const {
    return m_extendedProtocolDiscriminator;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {

    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_extendedProtocolDiscriminator =
        static_cast<ExtendedProtocolDiscriminator>(nasBuffer.DecodeU8());
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_extendedProtocolDiscriminator));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SecurityHeaderTypeIE : public InformationElement {
  SecurityHeaderType m_securityHdrType = SecurityHeaderType::NOT_PROTECTED;

public:
  size_t Size() const override { return sizeof(m_securityHdrType); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SECURITY_HEADER_TYPE;
  }

  void SetSecurityHeaderType(SecurityHeaderType sht) {
    m_securityHdrType = sht;
  }
  SecurityHeaderType GetSecurityHeaderType() const { 
    return m_securityHdrType; 
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    m_securityHdrType =
        static_cast<SecurityHeaderType>(nasBuffer.DecodeNibble());

    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_securityHdrType));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};
/*
class PduSessionIdentityIE : public InformationElement {
private:
  uint8_t m_pduSessionIdentity = 0x0;

public:
  PduSessionIdentityIE() {}

  size_t Size() const override { return sizeof(m_pduSessionIdentity); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PDU_SESSION_IDENTITY;
  }

  void SetPduSessionIdentity(uint8_t psi) { m_pduSessionIdentity = psi; }
  uint8_t GetPduSessionIdentity() const { return m_pduSessionIdentity; }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_pduSessionIdentity = nasBuffer.DecodeU8();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_pduSessionIdentity);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};
*/
class SpareHalfOctetIE : public InformationElement {
private:
  uint8_t m_spareHalfOctet = 0x0;

public:
  size_t Size() const override { return sizeof(m_spareHalfOctet); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SPARE_HALF_OCTET;
  }

  void SetSpareHalfOctet(uint8_t sho) { m_spareHalfOctet = sho; }
  uint8_t GetSpareHalfOctet() const { return m_spareHalfOctet; }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    m_spareHalfOctet = nasBuffer.DecodeNibble();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    nasBuffer.EncodeNibble(m_spareHalfOctet);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ProcedureTransactionIdentityIE : public InformationElement {
private:
  uint8_t m_procedureTransactionIdentity = 0x0;

public:
  size_t Size() const override {
    return sizeof(m_procedureTransactionIdentity);
  }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY;
  }

  void SetProcedureTransactionIdentity(uint8_t pti) {
    m_procedureTransactionIdentity = pti;
  }
  uint8_t GetProcedureTransactionIdentity() const {
    return m_procedureTransactionIdentity;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_procedureTransactionIdentity = nasBuffer.DecodeU8();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_procedureTransactionIdentity);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MessageTypeIE : public InformationElement {
private:
  MessageType m_msgType = MessageType::NOT_DEFINED;

public:
  size_t Size() const override { return sizeof(m_msgType); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_MESSAGE_TYPE;
  }

  void SetMessageType(MessageType type) { m_msgType = type; }
  MessageType GetMessageType() const { return m_msgType; }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_msgType = static_cast<MessageType>(nasBuffer.DecodeU8());
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_msgType));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MessageAuthenticationCodeIE : public InformationElement {
private:
  std::vector<uint8_t> m_messageAuthenticationCode;

public:
  size_t Size() const override { return m_messageAuthenticationCode.size(); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_MESSAGE_AUTHENTICATION_CODE;
  }

  void SetMessageAuthenticationCode(std::vector<uint8_t> mac) {
    m_messageAuthenticationCode = mac;
  }
  std::vector<uint8_t> GetMessageAuthenticationCode() const {
    return m_messageAuthenticationCode;
  }

  bool isEqual(std::vector<uint8_t> mac) const {
    return (mac == m_messageAuthenticationCode);
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    return nasBuffer.DecodeU8Vector(m_messageAuthenticationCode,
                                    MESSAGE_AUTHENTICATION_CODE_LENGTH);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8Vector(m_messageAuthenticationCode);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SequenceNumberIE : public InformationElement {
private:
  uint8_t m_SequenceNumber = 0x0;

public:
  size_t Size() const override { return sizeof(m_SequenceNumber); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SEQUENCE_NUMBER;
  }

  void SetSequenceNumber(uint8_t sqn) { m_SequenceNumber = sqn; }
  uint8_t GetSequenceNumber() const { return m_SequenceNumber; }

  bool isEqual(uint8_t sqn) const {
    return (sqn == m_SequenceNumber);
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_SequenceNumber = nasBuffer.DecodeU8();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_SequenceNumber);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class NasKeySetIdentifierIE : public InformationElement {
private:
  bool m_securityContextTypeFlag = false;
  uint8_t m_ngKSI = 0;

public:
  NasKeySetIdentifierIE() {}

  size_t Size() const override { return sizeof(m_ngKSI); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NAS_KEY_SET_IDENTIFIER;
  }
  void SetSecurityContextTypeFlag(bool tsc) { m_securityContextTypeFlag = tsc; }
  bool GetSecurityContextTypeFlag() const { return m_securityContextTypeFlag; }

  void SetNasKeySetIdentifier(uint8_t ngKSI) { m_ngKSI = ngKSI; }
  uint8_t GetNasKeySetIdentifier() const { return m_ngKSI; }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t ngKsi = nasBuffer.DecodeNibble();
    SetSecurityContextTypeFlag((ngKsi >> 3) & 0x1);
    SetNasKeySetIdentifier(ngKsi & 0x7);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t ngKsi = (static_cast<uint8_t>(m_securityContextTypeFlag) << 3) |
                    (m_ngKSI & 0x7);
    nasBuffer.EncodeNibble(ngKsi);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class NonCurrentNativeNasKeySetIdentifierIE: public NasKeySetIdentifierIE
{
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NON_CURRENT_NATIVE_NAS_KEY_SET_IDENTIFIER;
  }
};

class AdditionalInformationIE : public InformationElement {
private:
  std::vector<uint8_t> m_additionalInformation;

public:
  std::vector<uint8_t> getAdditionalInformation() const {
    return m_additionalInformation;
  }

  void  setAdditionalInformation(
    const std::vector<uint8_t> &mAdditionalInformation) {
    m_additionalInformation = mAdditionalInformation;
  }

  size_t Size() const override { return m_additionalInformation.size(); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ADDITIONAL_INFORMATION;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_additionalInformation, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_additionalInformation.size()));
    nasBuffer.EncodeU8Vector(m_additionalInformation);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AccessTypeIE : public InformationElement {
private:
  AccessType m_accessType = AccessType::THREEGPP_ACCESS;

public:
  size_t Size() const override { return sizeof(m_accessType); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ACCESS_TYPE;
  }

  AccessType getAccessType() const { return m_accessType; }
  void setAccessType(AccessType accessType) { m_accessType = accessType; }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_accessType = static_cast<AccessType>(nasBuffer.DecodeNibble());
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_accessType));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class DnnIE : public InformationElement {
private:
  std::vector<uint8_t> m_dnn;
  // province1.mnc012.mcc345.gprs

  NasCause DecodeDNN(const NasBuffer &nasBuffer) {
    uint8_t l = nasBuffer.DecodeU8();

    std::vector<uint8_t> dnn;

    if (NasCause::NAS_CAUSE_FAILURE == nasBuffer.DecodeU8Vector(dnn, l)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t dnn_len = dnn[0];

    while (dnn_len < l) {
      uint8_t next_dnn_len = dnn[dnn_len + 1];
      dnn[dnn_len + 1] = DOT_OPERATOR;
      dnn_len += next_dnn_len + 1;
    }
    m_dnn.assign(dnn.begin() + 1, dnn.end());

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause EncodeDNN(NasBuffer &nasBuffer) const {

    nasBuffer.EncodeU8(m_dnn.size() + 1);
    std::vector<uint8_t> dnn = m_dnn;
    size_t end = dnn.size();

    for (size_t i = end; i > 0; --i) {
      size_t cur_pos = i - 1;
      if (dnn[cur_pos] == DOT_OPERATOR) {
        dnn[cur_pos] = static_cast<uint8_t>(end - i);
        end = cur_pos;
      }
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(end));
    nasBuffer.EncodeU8Vector(dnn);
    return NasCause::NAS_CAUSE_SUCCESS;
  }

public:
  size_t Size() const override { return m_dnn.size(); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_DNN;
  }

  void SetDnn(const std::vector<uint8_t> &dnn) { m_dnn = dnn; }
  std::vector<uint8_t> GetDnn() const { return m_dnn; }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    DecodeDNN(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    EncodeDNN(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EapMessageIE : public InformationElement {
private:
  std::vector<uint8_t> m_eapMessage;

public:
  void SetEapMessage(const std::vector<uint8_t> &eapmsg) {
    m_eapMessage = eapmsg;
  }
  std::vector<uint8_t> GetEapMessage() const { return m_eapMessage; }

  size_t Size() const override { return m_eapMessage.size(); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EAP_MESSAGE;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    return nasBuffer.DecodeU8Vector(m_eapMessage, l);
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU16(static_cast<uint16_t>(m_eapMessage.size()));
    nasBuffer.EncodeU8Vector(m_eapMessage);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class GprsTimerIE : public InformationElement {
private:
  GprsTimerValueUnit m_gprsTimerValueUint =
      GprsTimerValueUnit::TIMER_IS_DEACTIVATED;
  uint8_t m_gprsTimerValue = 0;

public:
  size_t Size() const override { return sizeof(m_gprsTimerValue); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_GPRS_TIMER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_gprsTimerValueUint =
        static_cast<GprsTimerValueUnit>(nasBuffer.DecodeNibble());
    m_gprsTimerValue = nasBuffer.DecodeNibble();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_gprsTimerValueUint));
    nasBuffer.EncodeNibble(m_gprsTimerValue);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class GprsTimer2IE : public InformationElement {
private:
  uint8_t m_gprsTimer2value = 0x0;

public:
  size_t Size() const override { return sizeof(m_gprsTimer2value); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_GPRS_TIMER_2;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (1 != l) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_gprsTimer2value = nasBuffer.DecodeU8();

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (m_gprsTimer2value > 0) {
      nasBuffer.EncodeU8(static_cast<uint8_t>(0x1));
      nasBuffer.EncodeU8(m_gprsTimer2value);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class GprsTimer3IE : public InformationElement {
private:
  GprsTimer3ValueUnit m_gprsTimer3ValueUint = 
                    GprsTimer3ValueUnit::DEACTIVATED;
  uint8_t m_gprsTimer3Value = 0x0;

public:
  size_t Size() const override { return sizeof(m_gprsTimer3Value); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_GPRS_TIMER_3;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (1 != l) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_gprsTimer3ValueUint =
        static_cast<GprsTimer3ValueUnit>(nasBuffer.DecodeNibble());
    m_gprsTimer3Value = nasBuffer.DecodeNibble();

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (m_gprsTimer3Value > 0) {
      nasBuffer.EncodeU8(static_cast<uint8_t>(0x1));
      nasBuffer.EncodeNibble(static_cast<uint8_t>(m_gprsTimer3ValueUint));
      nasBuffer.EncodeNibble(m_gprsTimer3Value);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class RQTimerValueIE: public GprsTimerIE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_RQ_TIMER_VALUE;
  }

};

class T3512ValueIE: public GprsTimer3IE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_T3512_VALUE;
  }

};

class BackOffTimerValueIE: public GprsTimer3IE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_BACK_OFF_TIMER_VALUE;
  }

};

class Non3GPPDeregistrationTimerValueIE: public GprsTimer2IE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NON_3GPP_DEREGISTRATION_TIMER_VAL;
  }

};

class T3502ValueIE: public GprsTimer2IE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_T3502_VALUE;
  }
};

class T3346ValueIE: public GprsTimer2IE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_T3346_VALUE;
  }

};

class IntraN1ModeNasTransparentContainerIE : public InformationElement {
private:
  MessageAuthenticationCodeIE   m_messageAuthenticationCode;
  CipheringAlgorithmType        m_cipheringAlgType = CipheringAlgorithmType::EA0;
  IntegrityProtectionAlgorithmType m_integrityProtectAlgType =
                                  IntegrityProtectionAlgorithmType::IA0;
  bool                          m_kAMFChangeFlag = false;
  NasKeySetIdentifierIE         m_nasKeySetIdentifier;
  SequenceNumberIE              m_sequenceNumber;

#define INTRA_N1MODE_NAS_TRANSPARENT_CONTAINER_LEN 7
public:
  size_t Size() const override {
    return INTRA_N1MODE_NAS_TRANSPARENT_CONTAINER_LEN;
  }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_INTRA_N1_MODE_NAS_TRANSPARENT_CONTAINER;
  }

  CipheringAlgorithmType getMCipheringAlgType() const {
    return m_cipheringAlgType;
  }

  void setCipheringAlgType(CipheringAlgorithmType mCipheringAlgType) {
    m_cipheringAlgType = mCipheringAlgType;
  }

  IntegrityProtectionAlgorithmType getIntegrityProtectAlgType() const {
    return m_integrityProtectAlgType;
  }

  void setIntegrityProtectAlgType(
      IntegrityProtectionAlgorithmType mIntegrityProtectAlgType) {
    m_integrityProtectAlgType = mIntegrityProtectAlgType;
  }

  std::vector<uint8_t> getMessageAuthenticationCode() const {
    return m_messageAuthenticationCode.GetMessageAuthenticationCode();
  }

  void setMessageAuthenticationCode(
      std::vector<uint8_t> &mMessageAuthenticationCode) {
    m_messageAuthenticationCode.SetMessageAuthenticationCode(
        mMessageAuthenticationCode);
  }

  uint8_t getNasKeySetIdentifier() const {
    return m_nasKeySetIdentifier.GetNasKeySetIdentifier();
  }

  void setNasKeySetIdentifier(uint8_t mNasKeySetIdentifier) {
    m_nasKeySetIdentifier.SetNasKeySetIdentifier(mNasKeySetIdentifier);
  }

  uint8_t getSequenceNumber() const {
    return m_sequenceNumber.GetSequenceNumber();
  }

  void setSequenceNumber(uint8_t mSequenceNumber) {
    m_sequenceNumber.SetSequenceNumber(mSequenceNumber);
  }

  bool isKAmfChangeFlag() const { return m_kAMFChangeFlag; }

  void setKAmfChangeFlag(bool mKAmfChangeFlag) {
    m_kAMFChangeFlag = mKAmfChangeFlag;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();

    if (INTRA_N1MODE_NAS_TRANSPARENT_CONTAINER_LEN != l) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    m_messageAuthenticationCode.Decode(nasBuffer);
    m_cipheringAlgType =
        static_cast<CipheringAlgorithmType>(nasBuffer.DecodeNibble());
    m_integrityProtectAlgType =
        static_cast<IntegrityProtectionAlgorithmType>(nasBuffer.DecodeNibble());
    m_kAMFChangeFlag = (nasBuffer.DecodeNibble() & 0x1);
    m_nasKeySetIdentifier.Decode(nasBuffer);
    m_sequenceNumber.Decode(nasBuffer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(
        static_cast<uint8_t>(INTRA_N1MODE_NAS_TRANSPARENT_CONTAINER_LEN));
    m_messageAuthenticationCode.Encode(nasBuffer);
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_cipheringAlgType));
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_integrityProtectAlgType));
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_kAMFChangeFlag));
    m_nasKeySetIdentifier.Encode(nasBuffer);
    m_sequenceNumber.Encode(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class N1ModeToS1ModeNasTransparentContainerIE : public SequenceNumberIE {

public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::
        IE_N1_MODE_TO_S1_MODE_NAS_TRANSPARENT_CONTAINER;
  }
};
#if 0
class SNssaiIE : public InformationElement {
  /*<-----8Bits(SST)----><---32Bits(SD)---------->*/
 private:
  SNssaiContents m_sNssaiContents = SNssaiContents::SST;
  uint32_t m_sNssai = 0;
  uint32_t m_mappedHplmnSNssai = 0;

 protected:
 NasCause DecodeNssai(const NasBuffer& nasBuffer) {
    switch (m_sNssaiContents) {
      case SNssaiContents::SST: {
        m_sNssai = static_cast<uint32_t>(nasBuffer.DecodeU8());
        break;
      }
      case SNssaiContents::SST_AND_MAPPED_HPLMN_SST: {
        m_sNssai = static_cast<uint32_t>(nasBuffer.DecodeU8());
        m_mappedHplmnSNssai = static_cast<uint32_t>(nasBuffer.DecodeU8());
        break;
      }
      case SNssaiContents::SST_AND_SD: {
        m_sNssai = nasBuffer.DecodeU32();
        break;
      }
      case SNssaiContents::SST_AND_SD_AND_MAPPED_HPLMN_SST: {
        m_sNssai = nasBuffer.DecodeU32();
        m_mappedHplmnSNssai = static_cast<uint32_t>(nasBuffer.DecodeU8());
        break;
      }
      case SNssaiContents::SST_AND_SD_AND_MAPPED_HPLMN_SST_MAPPED_HPLMN_SD: {
        m_sNssai = nasBuffer.DecodeU32();
        m_mappedHplmnSNssai = nasBuffer.DecodeU32();
        break;
      }
      default: {
        break;
      }
    }
    return NasCause::NAS_CAUSE_SUCCESS;
 }
 NasCause EncodeNssai(NasBuffer& nasBuffer)const
 {
       switch (m_sNssaiContents) {
      case SNssaiContents::SST: {
        nasBuffer.EncodeU8(static_cast<uint8_t>(m_sNssai));
        break;
      }
      case SNssaiContents::SST_AND_MAPPED_HPLMN_SST: {
        nasBuffer.EncodeU8(static_cast<uint8_t>(m_sNssai));
        nasBuffer.EncodeU8(static_cast<uint8_t>(m_mappedHplmnSNssai));
        break;
      }
      case SNssaiContents::SST_AND_SD: {
        nasBuffer.EncodeU32(m_sNssai);
        break;
      }
      case SNssaiContents::SST_AND_SD_AND_MAPPED_HPLMN_SST: {
        nasBuffer.EncodeU32(m_sNssai);
        nasBuffer.EncodeU8(static_cast<uint8_t>(m_mappedHplmnSNssai));
        break;
      }
      case SNssaiContents::SST_AND_SD_AND_MAPPED_HPLMN_SST_MAPPED_HPLMN_SD: {
        nasBuffer.EncodeU32(m_sNssai);
        nasBuffer.EncodeU32(m_mappedHplmnSNssai);
        break;
      }
      default: {
        break;
      }
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

 public:
  void setSNssaiContents(SNssaiContents sNssaiContents) {
     m_sNssaiContents = sNssaiContents;
  }
  SNssaiContents getSNssaiContents() const {
    return m_sNssaiContents;
  }

  size_t Size() const override {
    return 0;
}

InformationElementType getInformationElementType() const override{
    return InformationElementType::IE_S_NSSAI;
  }
  size_t Size() {
     return static_cast<size_t>(m_sNssaiContents);
  }

  NasCause Decode(const NasBuffer& nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    
    m_sNssaiContents = static_cast<SNssaiContents>(nasBuffer.DecodeU8());
    DecodeNssai(nasBuffer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer& nasBuffer, bool isOptional = false) const override {
      if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_sNssaiContents));
    EncodeNssai(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

#endif

class SNssaiIE : public InformationElement {
  /*<-----8Bits(SST)----><---24Bits(SD)---------->*/
private:
  std::vector<uint8_t>  m_nssai;

public:
  size_t Size() const override { return m_nssai.size(); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_S_NSSAI;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_nssai, l);
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_nssai.size()));
    nasBuffer.EncodeU8Vector(m_nssai);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class S1ModeToN1ModeNasTransparentContainerIE : public InformationElement {
private:
  MessageAuthenticationCodeIE       m_messageAuthenticationCode;
  CipheringAlgorithmType            m_cipheringAlgType = CipheringAlgorithmType::EA0;
  IntegrityProtectionAlgorithmType  m_integrityProtectAlgType =
      IntegrityProtectionAlgorithmType::IA0;
  uint8_t                           m_nextHopChainingCounter = 0x0;
  NasKeySetIdentifierIE             m_nasKeySetIdentifier;
  uint16_t                          m_spareOctets = 0;

#define S1MODE_TO_N1MODE_NAS_TRANSPARENT_CONTAINER_LEN 8

public:
  size_t Size() const override {
    return S1MODE_TO_N1MODE_NAS_TRANSPARENT_CONTAINER_LEN;
  }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::
        IE_S1_MODE_TO_N1_MODE_NAS_TRANSPARENT_CONTAINER;
  }
  CipheringAlgorithmType getMCipheringAlgType() const {
    return m_cipheringAlgType;
  }

  void setCipheringAlgType(CipheringAlgorithmType mCipheringAlgType) {
    m_cipheringAlgType = mCipheringAlgType;
  }

  IntegrityProtectionAlgorithmType getIntegrityProtectAlgType() const {
    return m_integrityProtectAlgType;
  }

  void setIntegrityProtectAlgType(
      IntegrityProtectionAlgorithmType mIntegrityProtectAlgType) {
    m_integrityProtectAlgType = mIntegrityProtectAlgType;
  }

  std::vector<uint8_t> getMessageAuthenticationCode() const {
    return m_messageAuthenticationCode.GetMessageAuthenticationCode();
  }

  void setMessageAuthenticationCode(
      std::vector<uint8_t> &mMessageAuthenticationCode) {
    m_messageAuthenticationCode.SetMessageAuthenticationCode(
        mMessageAuthenticationCode);
  }

  uint8_t getNasKeySetIdentifier() const {
    return m_nasKeySetIdentifier.GetNasKeySetIdentifier();
  }

  void setNasKeySetIdentifier(uint8_t mNasKeySetIdentifier) {
    m_nasKeySetIdentifier.SetNasKeySetIdentifier(mNasKeySetIdentifier);
  }

  bool GetNextHopChainingCounter() const { return m_nextHopChainingCounter; }

  void SetNextHopChainingCounter(uint8_t nextHopChainingCounter) {
    m_nextHopChainingCounter = nextHopChainingCounter;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (l != S1MODE_TO_N1MODE_NAS_TRANSPARENT_CONTAINER_LEN) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_messageAuthenticationCode.Decode(nasBuffer);
    m_cipheringAlgType =
        static_cast<CipheringAlgorithmType>(nasBuffer.DecodeNibble());
    m_integrityProtectAlgType =
        static_cast<IntegrityProtectionAlgorithmType>(nasBuffer.DecodeNibble());
    m_nextHopChainingCounter = (nasBuffer.DecodeNibble() & 0x7);
    m_nasKeySetIdentifier.Decode(nasBuffer);
    m_spareOctets = nasBuffer.DecodeU16(); // SpareOctets

    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(S1MODE_TO_N1MODE_NAS_TRANSPARENT_CONTAINER_LEN);
    m_messageAuthenticationCode.Encode(nasBuffer);
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_cipheringAlgType));
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_integrityProtectAlgType));
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_nextHopChainingCounter));
    m_nasKeySetIdentifier.Encode(nasBuffer);
    nasBuffer.EncodeU16(m_spareOctets);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class FiveGmmCapabilityIE : public InformationElement {
private:
  uint8_t m_octet1 = 0x0;
 
  //optional buffer
  uint8_t m_octet2 = 0x0;
  uint8_t m_octet3 = 0x0;

  std::vector<uint8_t> m_spare;

public:
  size_t Size() const override { return m_spare.size() + 3 * sizeof(uint8_t); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GMM_CAPABILITY;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {

    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();

    m_octet1 = nasBuffer.DecodeU8();
    if (l > 1)
      m_octet2 = nasBuffer.DecodeU8();
    if (l > 2)
      m_octet3 = nasBuffer.DecodeU8();
    if (l > 3)
      return nasBuffer.DecodeU8Vector(m_spare, l - 3);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t l = m_spare.size() + 1 + (m_octet2 ? 1 : 0) + (m_octet3 ? 1 : 0);
    nasBuffer.EncodeU8(l);

    nasBuffer.EncodeU8(m_octet1);
    if (m_octet2)
      nasBuffer.EncodeU8(m_octet2);
    if (m_octet3)
      nasBuffer.EncodeU8(m_octet3);

    if (m_spare.size()) {
      nasBuffer.EncodeU8Vector(m_spare);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  bool isEpcNas() const { return NasUtils::getBit(m_octet1, 1); }
  void SetEpcNas() { NasUtils::setBit(m_octet1, 1); }

  bool isHandoverAttach() const { return NasUtils::getBit(m_octet1, 2); }
  void setHandoverAttach() { NasUtils::setBit(m_octet1, 2); }

  bool isLteLppCapability() const { return NasUtils::getBit(m_octet1, 3); }
  void setLteLppCapability() { NasUtils::setBit(m_octet1, 3); }

  bool isRestrictEnhancedCoverageSupport() const {
    return NasUtils::getBit(m_octet1, 4);
  }
  void setRestrictEnhancedCoverageSupport() { NasUtils::setBit(m_octet1, 4); }

  bool isControlPlaneCIoTOptimization() const {
    return NasUtils::getBit(m_octet1, 5);
  }
  void setControlPlaneCIoTOptimization() { NasUtils::setBit(m_octet1, 5); }

  bool isN3DataTransfer() const { return NasUtils::getBit(m_octet1, 6); }
  void setN3DataTransfer() { NasUtils::setBit(m_octet1, 6); }

  bool isIpHdrCompressionCpcIoTOptimization() const {
    return NasUtils::getBit(m_octet1, 7);
  }
  void setIpHdrCompressionCpcIoTOptimization() {
    NasUtils::setBit(m_octet1, 7);
  }

  bool isServiceGapControl() const { return NasUtils::getBit(m_octet1, 8); }
  void setServiceGapControl() { NasUtils::setBit(m_octet1, 8); }

  bool isSrvcc() const { return NasUtils::getBit(m_octet2, 1); }
  void setSrvcc(bool mSrvcc) { NasUtils::setBit(m_octet2, 1); }

  bool isUserPlaneCIoT() const { return NasUtils::getBit(m_octet2, 2); }
  void setUserPlaneCIoT() { NasUtils::setBit(m_octet2, 2); }

  bool isV2XCapability() const { return NasUtils::getBit(m_octet2, 3); }
  void setV2XCapability(bool mV2XCapability) { NasUtils::setBit(m_octet2, 3); }

  bool isV2XCommunicationOverEutrapc5() const {
    return NasUtils::getBit(m_octet2, 4);
  }
  void setV2XCommunicationOverEutrapc5() { NasUtils::setBit(m_octet2, 4); }

  bool isV2XCommunicationOverNrpc5() const {
    return NasUtils::getBit(m_octet2, 5);
  }
  void setV2XCommunicationOverNrpc5() { NasUtils::setBit(m_octet2, 5); }

  bool isLocationServices() const { return NasUtils::getBit(m_octet2, 6); }
  void setLocationServices() { NasUtils::setBit(m_octet2, 6); }

  bool isNetworkSlicSpecificAuthenticationAutheriozation() const {
    return NasUtils::getBit(m_octet2, 7);
  }
  void setNetworkSlicSpecificAuthenticationAutheriozation() {
    NasUtils::setBit(m_octet2, 7);
  }

  bool isRadioCapabilitySiganlling() const {
    return NasUtils::getBit(m_octet2, 8);
  }
  void setRadioCapabilitySiganlling() { NasUtils::setBit(m_octet2, 8); }

  bool isClosedAccessGroup() const { return NasUtils::getBit(m_octet3, 1); }
  void setClosedAccessGroup() { NasUtils::setBit(m_octet3, 1); }

  bool isWusAssistance() const { return NasUtils::getBit(m_octet3, 2); }
  void setWusAssistance() { NasUtils::setBit(m_octet3, 2); }

  bool isMultipleUserplaneResource() const {
    return NasUtils::getBit(m_octet3, 3);
  }
  void setMultipleUserplaneResource() { NasUtils::setBit(m_octet3, 3); }

  bool isEthernetHdrCompressionCpcIoTOptimization() const {
    return NasUtils::getBit(m_octet3, 4);
  }
  void setEthernetHdrCompressionCpcIoTOptimization() {
    NasUtils::setBit(m_octet3, 4);
  }
};

class FiveGmmCauseIE : public InformationElement {
  FiveGmmCause m_fiveGmmCause = FiveGmmCause::CAUSE_UNKNOWN;

public:
  size_t Size() const override { return sizeof(m_fiveGmmCause); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GMM_CAUSE;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_fiveGmmCause = static_cast<FiveGmmCause>(nasBuffer.DecodeU8());
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_fiveGmmCause));
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  FiveGmmCause getFiveGmmCause() const { return m_fiveGmmCause; }

  void setFiveGmmCause(FiveGmmCause mFiveGmmCause) {
    m_fiveGmmCause = mFiveGmmCause;
  }
};

class FiveGsDrxParametersIE : public InformationElement {
private:
  DrxValue m_drxParameters = DrxValue::NOT_SPECIFIED;

public:
  size_t Size() const override { return sizeof(m_drxParameters); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_DRX_PARAMETERS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (0x1 != l) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.DecodeNibble();
    m_drxParameters = static_cast<DrxValue>(nasBuffer.DecodeNibble());

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(0x1));
    nasBuffer.EncodeNibble(static_cast<uint8_t>(0x0));
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_drxParameters));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class RequestedDrxParametersIE : public FiveGsDrxParametersIE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_REQUESTED_DRX_PARAMETERS;
  }
};

class NegotiatedDrxParametersIE : public FiveGsDrxParametersIE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NEGOTIATED_DRX_PARAMETERS;
  }
};

class FiveGsIdentityTypeIE : public InformationElement {
  MobileIdentityType m_fiveGsIdentityType = MobileIdentityType::SUCI;

public:
  size_t Size() const override { return sizeof(m_fiveGsIdentityType); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_IDENTITY_TYPE;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_fiveGsIdentityType =
        static_cast<MobileIdentityType>(nasBuffer.DecodeNibble());
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_fiveGsIdentityType));
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  MobileIdentityType getFiveGsIdentityType() const {
    return m_fiveGsIdentityType;
  }

  void setFiveGsIdentityType(MobileIdentityType mFiveGsIdentityType) {
    m_fiveGsIdentityType = mFiveGsIdentityType;
  }
};

class PlmnIdentity {
private:
  uint16_t m_mcc = 0;
  uint16_t m_mnc = 0;

public:
  size_t Size() const { return PLMN_IDENTITY_SIZE; }
  uint16_t getMcc() const { return m_mcc; }

  void setMcc(uint16_t mMcc) { m_mcc = mMcc; }

  uint16_t getMnc() const { return m_mnc; }

  void setMnc(uint16_t mMnc) { m_mnc = mMnc; }

  NasCause Decode(const NasBuffer &nasBuffer) {
    m_mcc = 0x0000;
    uint8_t o1 = nasBuffer.DecodeU8();
    if ((o1 & 0x0F) != 0x0F) {
      m_mcc = static_cast<uint16_t>(o1 & 0x0F);
    }
    if ((o1 & 0xF0) != 0xF0) {
      m_mcc = static_cast<uint16_t>((m_mcc * 10) + ((o1 & 0xF0) >> 4));
    }
    uint8_t o2 = nasBuffer.DecodeU8();
    if ((o2 & 0x0F) != 0x0F) {
      m_mcc = static_cast<uint16_t>((m_mcc * 10) + (o2 & 0x0F));
    }

    m_mnc = 0x0000;
    if ((o2 & 0xF0) != 0xF0) {
      m_mnc = ((static_cast<uint16_t>(o2 & 0xF0)) >> 4);
    }
    uint8_t o3 = nasBuffer.DecodeU8();
    if ((o3 & 0x0F) != 0x0F) {
      m_mnc = (static_cast<uint16_t>((m_mnc * 10) + (o3 & 0x0F)));
    }
    if ((o3 & 0xF0) != 0xF0) {
      m_mnc = (static_cast<uint16_t>((m_mnc * 10) + ((o3 & 0xF0) >> 4)));
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    uint8_t v = 0xFF;
    if ((m_mcc / 100) != 0) {
      v = (v & 0xF0) | static_cast<uint8_t>((m_mcc / 100) & 0x000F);
    }
    if ((((m_mcc / 10) % 10) != 0) || (m_mcc / 100)) {
      v = (v & 0x0F) | ((static_cast<uint8_t>((m_mcc / 10) % 10)) << 4);
    }
    nasBuffer.EncodeU8(v);

    v = 0xFF;
    if (((m_mcc % 10) != 0) || (m_mcc / 10)) {
      v = (v & 0xF0) | static_cast<uint8_t>(m_mcc % 10);
    }
    if ((m_mnc / 100) != 0) {
      v = (v & 0x0F) | ((static_cast<uint8_t>(m_mnc / 100)) << 4);
    }
    nasBuffer.EncodeU8(v);
    v = 0xFF;
    if ((((m_mnc / 10) % 10) != 0) || (m_mnc / 100)) {
      v = (v & 0xF0) | static_cast<uint8_t>((m_mnc / 10) % 10);
    }
    if (((m_mnc % 10) != 0) || (m_mnc / 10)) {
      v = (v & 0x0F) | static_cast<uint8_t>((m_mnc % 10) << 4);
    }
    nasBuffer.EncodeU8(v);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  void Clear() {
    m_mcc = 0;
    m_mnc = 0;
  }
};

class RoutingIndicator {
  private:
     uint16_t m_routingIndicator = 0x0;
  public:
  size_t Size() const {
    return sizeof(m_routingIndicator);
  }
  NasCause Decode(const NasBuffer &nasBuffer) { 
    uint8_t octet = 0x0;

    octet = nasBuffer.DecodeU8();
    if ((octet & 0x0F) != 0x0F)
      m_routingIndicator = (static_cast<uint16_t>(octet & 0x0F));
    if (((octet & 0xF0) != 0xF0) || m_routingIndicator)
      m_routingIndicator = (m_routingIndicator * 10) +
                           (static_cast<uint16_t>((octet & 0xF0) >> 4));

    octet = nasBuffer.DecodeU8();
    if (((octet & 0x0F) != 0x0F) || m_routingIndicator)
      m_routingIndicator = (m_routingIndicator * 10) +
                           (static_cast<uint16_t>(octet & 0x0F));
    if (((octet & 0xF0) != 0xF0) || m_routingIndicator)
      m_routingIndicator = (m_routingIndicator * 10) +
                           (static_cast<uint16_t>((octet & 0xF0) >> 4));
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer) const {
    //uint8_t v = 0xFF;
    uint8_t v = 0x00;
    if ((m_routingIndicator / 1000) || (m_routingIndicator == 0))
      v = (v & 0xF0) |
          static_cast<uint8_t>((m_routingIndicator / 1000) & 0x000F);
    if ((m_routingIndicator / 100) % 10 || (m_routingIndicator / 1000))
      v = (v & 0x0F) |
          (static_cast<uint8_t>(((m_routingIndicator / 100) % 10) << 4));
    nasBuffer.EncodeU8(v);

    //v = 0xFF;
    v = 0x00;
    if ((m_routingIndicator / 100) / 10 || (m_routingIndicator / 100))
      v = (v & 0xF0) | static_cast<uint8_t>((m_routingIndicator / 100) / 10);
    if ((m_routingIndicator % 10) || (m_routingIndicator / 1000))
      v = (v & 0x0F) | (static_cast<uint8_t>((m_routingIndicator % 10) << 4));
    nasBuffer.EncodeU8(v);
    
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MobileIdentity {
private:
  MobileIdentityType m_MobileIdentityType = MobileIdentityType::NO_IDENTITY;

public:
  virtual NasCause Decode(const NasBuffer &nasBuffer, uint16_t l) = 0;
  virtual NasCause Encode(NasBuffer &nasBuffer) const = 0;
  virtual ~MobileIdentity() {}

  virtual size_t Size() const = 0;

  MobileIdentityType getMobileIdentityType() const {
    return m_MobileIdentityType;
  }

  void setMobileIdentityType(MobileIdentityType mIdentityType) {
    m_MobileIdentityType = mIdentityType;
  }
};

class MobileIdentitySUCI : public MobileIdentity {
private:
  SupiFormat m_supiFormat = SupiFormat::IMSI;

  PlmnIdentity m_plmnIdentity;
  RoutingIndicator m_routingIndicator;
  ProtectionSchemeIdentifier m_protectionScheme =
      ProtectionSchemeIdentifier::NULL_SCHEME;
  uint8_t m_spare = 0x0;
  uint8_t m_homeNetworkPublicKeyIdentifier = 0;
  std::vector<uint8_t> m_schemeOuput;

public:

  size_t Size() const override {
      size_t s = m_schemeOuput.size();
      s = (s & 1)?(s/2 + 1):(s/2);
      s +=  (sizeof(uint8_t) + // supi format + identity type
             m_plmnIdentity.Size() +
             m_routingIndicator.Size() + 
             sizeof(uint8_t) + //protection scheme 
             sizeof(m_homeNetworkPublicKeyIdentifier));
      return s;
  }

  uint8_t getHomeNetworkPublicKeyIdentifier() const {
    return m_homeNetworkPublicKeyIdentifier;
  }

  void
  setHomeNetworkPublicKeyIdentifier(uint8_t mHomeNetworkPublicKeyIdentifier) {
    m_homeNetworkPublicKeyIdentifier = mHomeNetworkPublicKeyIdentifier;
  }

  ProtectionSchemeIdentifier getProtectionScheme() const {
    return m_protectionScheme;
  }

  void setProtectionScheme(ProtectionSchemeIdentifier mProtectionScheme =
                               ProtectionSchemeIdentifier::NULL_SCHEME) {
    m_protectionScheme = mProtectionScheme;
  }

  std::vector<uint8_t> getSchemeOuput() const { return m_schemeOuput; }

  void setSchemeOuput(std::vector<uint8_t> mSchemeOuput) {
    m_schemeOuput = mSchemeOuput;
  }

  SupiFormat getSupiFormat() const { return m_supiFormat; }

  void setSupiFormat(SupiFormat mSupiFormat) { m_supiFormat = mSupiFormat; }

  NasCause Decode(const NasBuffer &nasBuffer, uint16_t l) override {

    m_supiFormat = static_cast<SupiFormat>(nasBuffer.DecodeNibble() & 0x7);
    setMobileIdentityType(static_cast<MobileIdentityType>(nasBuffer.DecodeNibble() & 0x7));
    

    m_plmnIdentity.Decode(nasBuffer);
    m_routingIndicator.Decode(nasBuffer);

    m_protectionScheme =
        static_cast<ProtectionSchemeIdentifier>(nasBuffer.DecodeNibble());
    m_spare = nasBuffer.DecodeNibble();

    m_homeNetworkPublicKeyIdentifier = nasBuffer.DecodeU8();

    for (uint16_t i = 0; i < (l-8); ++i) {
      uint8_t v = nasBuffer.DecodeU8();
      m_schemeOuput.emplace_back(v & 0x0F);
      m_schemeOuput.emplace_back((v & 0xF0) >> 4);
    }

    if(m_schemeOuput.back() == 0x0F) {
      m_schemeOuput.pop_back();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const override {
    
    nasBuffer.EncodeNibble((static_cast<uint8_t>(m_supiFormat)) & 0x7);
    nasBuffer.EncodeNibble(static_cast<uint8_t>(getMobileIdentityType()) & 0x7);
    
    
    m_plmnIdentity.Encode(nasBuffer);
    m_routingIndicator.Encode(nasBuffer);
 
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_protectionScheme) & 0x0F);
    nasBuffer.EncodeNibble(m_spare);

    nasBuffer.EncodeU8(static_cast<uint8_t>(m_homeNetworkPublicKeyIdentifier));

    size_t l = m_schemeOuput.size();
    uint8_t v = 0x0;
    for (size_t i = 0; i < l-1; i += 2) {
      v = (m_schemeOuput[i] & 0x0F) | ((m_schemeOuput[i + 1] & 0x0F) << 4);
      nasBuffer.EncodeU8(v);
    }
    if (l & 1) {
      v = 0xF0;
      v = v | (m_schemeOuput[l - 1] & 0x0F);
      nasBuffer.EncodeU8(v);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MobileIdentityGUTI : public MobileIdentity {
private:
  PlmnIdentity m_plmnIdentity;
  uint8_t m_amfRegionId = 0; // octet 8
  uint16_t m_amfSetId = 0;   // octet 9, octet 10 bits 7 to 8
  uint8_t m_amfPointer = 0;  // octet 10 bits 1 to 6
  std::vector<uint8_t> m_tmsi;

public:
  size_t Size() const override {
      return sizeof(uint8_t) +
             m_plmnIdentity.Size() +
             sizeof(m_amfRegionId) + 
             sizeof(m_amfSetId) +
             m_tmsi.size();
  }
  uint8_t getAmfPointer() const { return m_amfPointer; }

  void setAmfPointer(uint8_t mAmfPointer) { m_amfPointer = mAmfPointer; }

  uint8_t getAmfRegionId() const { return m_amfRegionId; }

  void setAmfRegionId(uint8_t mAmfRegionId) { m_amfRegionId = mAmfRegionId; }

  uint16_t getAmfSetId() const { return m_amfSetId; }

  void setAmfSetId(uint16_t mAmfSetId) { m_amfSetId = mAmfSetId; }

  std::vector<uint8_t> getTmsi() const { return m_tmsi; }

  void setTmsi(const std::vector<uint8_t> &mTmsi) { m_tmsi = mTmsi; }

  NasCause Decode(const NasBuffer &nasBuffer, uint16_t l) override {
    nasBuffer.DecodeNibble();
    setMobileIdentityType(static_cast<MobileIdentityType>(nasBuffer.DecodeNibble() & 0x7));

    m_plmnIdentity.Decode(nasBuffer);

    m_amfRegionId = nasBuffer.DecodeU8();

    uint16_t v = nasBuffer.DecodeU8();
    uint8_t v1 = nasBuffer.DecodeU8();
    v = (v << 2) | ((v1 >> 6) & 0b11);
    m_amfSetId = v;

    m_amfPointer = v1 & 0b111111;
    nasBuffer.DecodeU8Vector(m_tmsi, l-7);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const override {
    nasBuffer.EncodeNibble(0xF);
    nasBuffer.EncodeNibble(static_cast<uint8_t>(getMobileIdentityType()) & 0x7);
    
    
    m_plmnIdentity.Encode(nasBuffer);
    nasBuffer.EncodeU8(m_amfRegionId);

    uint8_t v = 0x0;
    v = static_cast<uint8_t>((m_amfSetId >> 2) & 0xFF);
    nasBuffer.EncodeU8(v);

    v = 0x0;
    v = ((static_cast<uint8_t>(m_amfSetId & 0b11)) << 6) |
        (m_amfPointer & 0b111111);
    nasBuffer.EncodeU8(v);

    nasBuffer.EncodeU8Vector(m_tmsi);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MobileIdentitySTMSI : public MobileIdentityGUTI {};

class MobileIdentityIMEI : public MobileIdentity {
  std::vector<uint8_t> m_imei;
  bool m_is_odd_indicator = false;
public:
  size_t Size() const override {
      return m_imei.size()/2 + 1; 
  }
  NasCause Decode(const NasBuffer &nasBuffer, uint16_t l) override {
    uint8_t v = nasBuffer.DecodeU8();
    setMobileIdentityType(static_cast<MobileIdentityType>(v & 0x7));
    bool m_is_odd_indicator = NasUtils::getBit(v, 4);
    
    m_imei.emplace_back((v & 0xF0) >> 4);

    for (uint16_t i = 0; i < l-1; ++i) {
      v = nasBuffer.DecodeU8();
      m_imei.emplace_back(v & 0x0F);
      m_imei.emplace_back((v & 0xF0)>>4);
    }
    if(!m_is_odd_indicator) {
        m_imei.pop_back();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const override {
    uint8_t v = 0x00;
    if(m_is_odd_indicator) {
        NasUtils::setBit(v, 4);
    }
    v = v | (static_cast<uint8_t>(getMobileIdentityType()) & 0x7);
    nasBuffer.EncodeU8(((m_imei[0] & 0xF) << 4) | v);

    uint8_t l = m_imei.size();
    for (uint8_t x = 1; x < l-1 ; x = x+2) {
      v = (m_imei[x] & 0x0F) | ((m_imei[x + 1] & 0x0F) << 4);
      nasBuffer.EncodeU8(v);
    }
    if (!m_is_odd_indicator) {
      v = 0xF0;
      v |=  (m_imei[m_imei.size() - 1] & 0x0F);
      nasBuffer.EncodeU8(v);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MobileIdentityIMEISV : public MobileIdentityIMEI {};

class MobileIdentityMacAddress : public MobileIdentity {
private:
  std::vector<uint8_t> m_macAddress;
  bool m_macAURI = false;

public:
  size_t Size() const override {
      return 0;
  }
  NasCause Decode(const NasBuffer &nasBuffer, uint16_t l) override {
    uint8_t v = nasBuffer.DecodeNibble();
    setMobileIdentityType(static_cast<MobileIdentityType>(v & 0x7));
    m_macAURI = (v >> 3) & 1;
    nasBuffer.DecodeNibble();
    nasBuffer.DecodeU8Vector(m_macAddress, l-1);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer  &nasBuffer) const override {
    uint8_t v = 0x00;
    v = v | ((static_cast<uint8_t>(m_macAURI)) & 0b1000);
    v = v | (static_cast<uint8_t>(getMobileIdentityType()) & 0x7);
    nasBuffer.EncodeU8(v);

    nasBuffer.EncodeU8Vector(m_macAddress);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};
class MobileIdentityEUI64 : public MobileIdentity {
  std::vector<uint8_t> m_eUI64;

public:
  size_t Size() const override {
      return 0;
  }
  NasCause Decode(const NasBuffer  &nasBuffer, uint16_t l) override {
    setMobileIdentityType(static_cast<MobileIdentityType>(nasBuffer.DecodeNibble() & 0x7));
    nasBuffer.DecodeNibble();
    nasBuffer.DecodeU8Vector(m_eUI64, l-1);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const override {
    uint8_t v = 0x00;
    v = v | (static_cast<uint8_t>(getMobileIdentityType()) & 0x7);
    nasBuffer.EncodeU8(v);
    nasBuffer.EncodeU8Vector(m_eUI64);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};
class MobileIdentityNoIdentity : public MobileIdentity {
public:
  size_t Size() const override {
      return 0;
  }
  NasCause Decode(const NasBuffer &nasBuffer, u_int16_t l) override {
    setMobileIdentityType(static_cast<MobileIdentityType>(nasBuffer.DecodeNibble() & 0x7));
    nasBuffer.DecodeNibble();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const override {
    uint8_t v = 0x00;
    v = v | (static_cast<uint8_t>(getMobileIdentityType()) & 0x7);
    nasBuffer.EncodeU8(v);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};
class MobileIdentityFactory {
public:
  static std::shared_ptr<MobileIdentity> AllocMobileIdentity(MobileIdentityType identityType) {
    
    std::shared_ptr<MobileIdentity> mobileIdentity ;

    switch (identityType) {
    case MobileIdentityType::GUTI: {
      mobileIdentity = std::make_shared<MobileIdentityGUTI>();
      break;
    }
    case MobileIdentityType::S_TMSI: {
      mobileIdentity = std::make_shared<MobileIdentitySTMSI>();
      break;
    }
    case MobileIdentityType::IMEI: {
      mobileIdentity = std::make_shared<MobileIdentityIMEI>();
      break;
    }
    case MobileIdentityType::IMEISV: {
      mobileIdentity = std::make_shared<MobileIdentityIMEISV>();
      break;
    }
    case MobileIdentityType::SUCI: {
      mobileIdentity = std::make_shared<MobileIdentitySUCI>();
      break;
    }
    case MobileIdentityType::MAC_ADDRESS: {
      mobileIdentity = std::make_shared<MobileIdentityMacAddress>();
      break;
    }
    case MobileIdentityType::EUI_64: {
      mobileIdentity = std::make_shared<MobileIdentityEUI64>();
      break;
    }
    case MobileIdentityType::NO_IDENTITY: {
      mobileIdentity = std::make_shared<MobileIdentityNoIdentity>();
      break;
    }
    default: {
      break;
    }
    }
    return mobileIdentity;
  }
};

class MobileIdentityIE : public InformationElement {
private:
  std::shared_ptr<MobileIdentity> m_mobileIdentity;

public:
  MobileIdentityIE() {}
  ~MobileIdentityIE() { }

  size_t Size() const override { return m_mobileIdentity->Size(); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_MOBILE_IDENTITY;
  }
  void SetMobileIdentityType(MobileIdentityType type) {
    m_mobileIdentity->setMobileIdentityType(type);
  }
  MobileIdentityType GetMobileIdentityType() {
    return m_mobileIdentity->getMobileIdentityType();
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();

    MobileIdentityType idType =
        static_cast<MobileIdentityType>(nasBuffer.GetCurrentOctet() & 0x07);
    m_mobileIdentity = MobileIdentityFactory::AllocMobileIdentity(idType);
    if (!m_mobileIdentity) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    m_mobileIdentity->Decode(nasBuffer, l);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (!m_mobileIdentity) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    nasBuffer.EncodeU16(m_mobileIdentity->Size());
    
    m_mobileIdentity->Encode(nasBuffer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class FiveGGutiIE: public MobileIdentityIE {
  public:
    InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5G_GUTI;
  }
};

class AdditionalGutiIE: public MobileIdentityIE {
  public:
    InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ADDITIONAL_GUTI;
  }
};

class ImeiSvIE: public MobileIdentityIE {
  public:
    InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_IMEISV;
  }
};

class FiveGsNetworkFeatureSupportIE : public InformationElement {
private:
  uint8_t m_octet1 = 0x0;
  uint8_t m_octet2 = 0x0;
  uint8_t m_octet3 = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (3 != l) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_octet1 = nasBuffer.DecodeU8();
    m_octet2 = nasBuffer.DecodeU8();
    m_octet3 = nasBuffer.DecodeU8();

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_octet1);
    nasBuffer.EncodeU8(m_octet2);
    nasBuffer.EncodeU8(m_octet3);

    return NasCause::NAS_CAUSE_SUCCESS;
  }

  void setImsVoiceOverPsSession3Gpp() { NasUtils::setBit(m_octet1, 1); }

  bool isImsVoiceOverPsSession3Gpp() const {
    return NasUtils::getBit(m_octet1, 1);
  }

  void setImsVoiceOverPsSessionNon3Gpp() { NasUtils::setBit(m_octet1, 2); }

  bool isImsVoiceOverPsSessionNon3Gpp() const {
    return NasUtils::getBit(m_octet1, 2);
  }

  EmergencyServiceSupport3gppIndicator getEmergencyServiceSupport() const {
    return static_cast<EmergencyServiceSupport3gppIndicator>(
        (m_octet1 & 0b00001100) >> 2);
  }

  void setEmergencyServiceSupport(
      EmergencyServiceSupport3gppIndicator mEmergencyServiceSupport) {
    m_octet1 =
        (m_octet1 & 0b11110011) |
        (((static_cast<uint8_t>(mEmergencyServiceSupport)) & 0b00000011) << 2);
  }

  EmergencyServiceFallback3gppIndicator getEmergencyServiceFallback() const {
    return static_cast<EmergencyServiceFallback3gppIndicator>(
        (m_octet1 & 0b00110000) >> 4);
  }

  void setEmergencyServiceFallback(
      EmergencyServiceFallback3gppIndicator mEmergencyServiceFallback) {
    m_octet1 =
        (m_octet1 & 0b11001111) |
        (((static_cast<uint8_t>(mEmergencyServiceFallback)) & 0b00000011) << 4);
  }

  bool isInterworkingWithoutN26() const {
    return NasUtils::getBit(m_octet1, 7);
  }

  void setInterworkingWithoutN26() { NasUtils::setBit(m_octet1, 7); }

  bool isMpsIndicator() const { return NasUtils::getBit(m_octet1, 8); }

  void setMpsIndicator() { NasUtils::setBit(m_octet1, 8); }

  bool isEmergencyServiceSupportNon3gppIndicator() const {
    return NasUtils::getBit(m_octet2, 1);
  }

  void setEmergencyServiceSupportNon3gppIndicator(
      bool mEmergencyServiceSupportNon3gppIndicator) {
    NasUtils::setBit(m_octet2, 1);
  }

  bool isMcsIndicator() const { return NasUtils::getBit(m_octet2, 2); }

  void setMcsIndicator(bool mMcsIndicator) { NasUtils::setBit(m_octet2, 2); }

  RestrictionOnEnhancedCoverage getRestrictedEnhancedCoverage() const {
    return static_cast<RestrictionOnEnhancedCoverage>((m_octet2 & 0b00001100) >>
                                                      2);
  }

  void setRestrictedEnhancedCoverage(
      RestrictionOnEnhancedCoverage mRestrictedEnhancedCoverage) {
    m_octet2 =
        (m_octet1 & 0b11110011) |
        (((static_cast<uint8_t>(mRestrictedEnhancedCoverage)) & 0b00000011)
         << 2);
  }

  bool isControlPlaneCIoT() const { return NasUtils::getBit(m_octet2, 5); }

  void setControlPlaneCIoT() { NasUtils::setBit(m_octet2, 5); }

  bool isN3DataTransfer() const { return NasUtils::getBit(m_octet2, 6); }

  void setN3DataTransfer(bool mN3DataTransfer) {
    NasUtils::setBit(m_octet2, 6);
  }

  bool isIpHdrCompressionCpcIoTOptimization() const {
    return NasUtils::getBit(m_octet2, 7);
  }

  void setIpHdrCompressionCpcIoTOptimization() {
    NasUtils::setBit(m_octet2, 7);
  }

  bool isUserPlaneCIoT() const { return NasUtils::getBit(m_octet2, 8); }

  void setUserPlaneCIoT(bool mUserPlaneCIoT) { NasUtils::setBit(m_octet2, 8); }

  bool isLocationServices() const { return NasUtils::getBit(m_octet3, 1); }

  void setLocationServices(bool mLocationServices) {
    NasUtils::setBit(m_octet3, 1);
  }

  bool isAtsIndicator() const { return NasUtils::getBit(m_octet3, 2); }

  void setAtsIndicator(bool mAtsIndicator) { NasUtils::setBit(m_octet3, 2); }

  bool isEthernetHdrCompressionCpcIoTOptimization() const {
    return NasUtils::getBit(m_octet3, 3);
  }

  void setEthernetHdrCompressionCpcIoTOptimization(
      bool mEthernetHdrCompressionCpcIoTOptimization) {
    NasUtils::setBit(m_octet3, 3);
  }
};

class FiveGsRegistrationResultIE : public InformationElement {
  uint8_t m_octet1 = 0;

public:
  size_t Size() const override { return sizeof(m_octet1); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_REGISTRATION_RESULT;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if(l) {
      m_octet1 = nasBuffer.DecodeU8();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(sizeof(m_octet1));
    nasBuffer.EncodeU8(m_octet1);
    
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  FivegsRegistrationResult getRegistrationResult() const {
    return static_cast<FivegsRegistrationResult>(m_octet1 & 0b00000111);
  }

  void setRegistrationResult(FivegsRegistrationResult mRegistrationResult) {
    m_octet1 = (m_octet1 & 0b11111000) |
               ((static_cast<uint8_t>(mRegistrationResult)) & 0b00000111);
  }

  bool isSmsOverNas() const { return NasUtils::getBit(m_octet1, 4); }

  void setSmsOverNas(bool mSmsOverNas) { NasUtils::setBit(m_octet1, 4); }

  bool isNssaaPerformed() const { return NasUtils::getBit(m_octet1, 5); }

  void setNssaaPerformed(bool mNssaa) { NasUtils::setBit(m_octet1, 5); }

  bool isEmergencyRegistered() const { return NasUtils::getBit(m_octet1, 6); }

  void setEmergencyRegistered(bool mEmergencyRegistered) {
    NasUtils::setBit(m_octet1, 6);
  }
};

class FiveGSRegistrationTypeIE : public InformationElement {
private:
  bool m_followOnRequestBit = false;
  RegistrationType m_registrationType = RegistrationType::INITIAL_REGISTRATION;

public:
  FiveGSRegistrationTypeIE() {}

  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_REGISTRATION_TYPE;
  }

  void SetFollowOnRequestBit(bool forb) { m_followOnRequestBit = forb; }
  bool GetFollowOnRequestBit() const { return m_followOnRequestBit; }

  void SetRegistrationType(RegistrationType regType) {
    m_registrationType = regType;
  }
  RegistrationType GetRegistrationType() const { return m_registrationType; }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    uint8_t lowerNibble = nasBuffer.DecodeNibble();
    SetFollowOnRequestBit((lowerNibble >> 3) & 1);
    SetRegistrationType(static_cast<RegistrationType>(lowerNibble & 0x7));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    uint8_t regType = (m_followOnRequestBit << 3) |
                      (static_cast<uint8_t>(m_registrationType));
    nasBuffer.EncodeNibble(regType);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class TrackingAreaCode {
  std::vector<uint8_t> m_tac;
  public:
    
  #define TRACKING_AREA_CODE_LEN 3
  size_t Size() const  { return TRACKING_AREA_CODE_LEN; }
  NasCause Decode(const NasBuffer &nasBuffer) {
  
    return nasBuffer.DecodeU8Vector(m_tac, TRACKING_AREA_CODE_LEN);
  }

  NasCause Encode(NasBuffer &nasBuffer) const {

    nasBuffer.EncodeU8Vector(m_tac);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  void Clear() {
    m_tac.clear();
  }
};

class FiveGsTrackingAreaIdentityIE : public InformationElement {
private:
  PlmnIdentity m_plmnIdentity;
  TrackingAreaCode m_trackingAreaCode;
#define TRACKING_AREA_CODE_LEN 3
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    m_plmnIdentity.Decode(nasBuffer);
    m_trackingAreaCode.Decode(nasBuffer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_plmnIdentity.Encode(nasBuffer);
    m_trackingAreaCode.Encode(nasBuffer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class LastVisitedRegisteredTaiIE : public FiveGsTrackingAreaIdentityIE
{
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_LAST_VISITED_REGISTERED_TRACKING_AREA_IDENTITY;
  }
};

// class PartialTrackingAreaIdentity {
// private:
//   PlmnIdentity      m_plmnIdentity;
//   TrackingAreaCode  m_trackingAreaCode;

// public:
//   NasCause DecodePLMN(const NasBuffer &nasBuffer) {
//     m_plmnIdentity.Decode(nasBuffer);
//     return NasCause::NAS_CAUSE_SUCCESS;
//   }
//   NasCause DecodeTAC(const NasBuffer &nasBuffer) {
//     return m_trackingAreaCode.Decode(nasBuffer);
//   }

//   NasCause EncodePLMN(NasBuffer &nasBuffer) const {

//     m_plmnIdentity.Encode(nasBuffer);

//     return NasCause::NAS_CAUSE_SUCCESS;
//   }
//   NasCause EncodeTAC(NasBuffer &nasBuffer) const {
//     m_trackingAreaCode.Encode(nasBuffer);
//     return NasCause::NAS_CAUSE_SUCCESS;
//   }
  
//   void Clear() {
//     m_plmnIdentity.Clear();
//     m_trackingAreaCode.Clear();
//   }
// };

class PartialTrackingAreaIdentity {
private:
  PlmnIdentity      m_plmnIdentity;
  TrackingAreaCode  m_trackingAreaCode;

public:
  NasCause DecodePLMN(const NasBuffer &nasBuffer) {
    m_plmnIdentity.Decode(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause DecodeTAC(const NasBuffer &nasBuffer) {
    return m_trackingAreaCode.Decode(nasBuffer);
  }

  NasCause EncodePLMN(NasBuffer &nasBuffer) const {

    m_plmnIdentity.Encode(nasBuffer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause EncodeTAC(NasBuffer &nasBuffer) const {
    m_trackingAreaCode.Encode(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  PlmnIdentity GetPlmnIdenity() const {
    return m_plmnIdentity;
  }
  TrackingAreaCode GetTrackingAreaCode() const {
    return m_trackingAreaCode;
  }

  void Clear() {
    m_plmnIdentity.Clear();
    m_trackingAreaCode.Clear();
  }
};


class PartialTrackingAreaIdentityList  {

  PartialTrackingAreaIdentityListType m_ptaiListType =
      PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_00;
  std::vector<PartialTrackingAreaIdentity> m_partialTaiList;


  NasCause
  DecodePartialTrackingAreaIdentityListType00(const NasBuffer &nasBuffer,
                                              size_t taiListSize) {
    PartialTrackingAreaIdentity partialTAI;
    partialTAI.DecodePLMN(nasBuffer);
    size_t l = 0;
    while (l < taiListSize) {
      partialTAI.DecodeTAC(nasBuffer);
      m_partialTaiList.emplace_back(partialTAI);
      partialTAI.Clear();
      l++;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause
  DecodePartialTrackingAreaIdentityListType01(const NasBuffer &nasBuffer,
                                              size_t taiListSize) {

    PartialTrackingAreaIdentity partialTAI;
    partialTAI.DecodePLMN(nasBuffer);
    partialTAI.DecodeTAC(nasBuffer);
    m_partialTaiList.emplace_back(partialTAI);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause
  DecodePartialTrackingAreaIdentityListType10(const NasBuffer &nasBuffer,
                                              size_t taiListSize) {
    size_t l = 0;
    while (l < taiListSize) {
      PartialTrackingAreaIdentity partialTAI;
      partialTAI.DecodePLMN(nasBuffer);
      partialTAI.DecodeTAC(nasBuffer);
      m_partialTaiList.emplace_back(partialTAI);
      partialTAI.Clear();
      l++;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }


  NasCause
  EncodePartialTrackingAreaIdentityListType00(NasBuffer &nasBuffer) const {
    m_partialTaiList[0].EncodePLMN(nasBuffer);
    size_t l = 0;
    while (l < m_partialTaiList.size()) {
      m_partialTaiList[l].EncodeTAC(nasBuffer);
      l++;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause
  EncodePartialTrackingAreaIdentityListType01(NasBuffer &nasBuffer) const {
    m_partialTaiList[0].EncodePLMN(nasBuffer);
    m_partialTaiList[0].EncodeTAC(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause
  EncodePartialTrackingAreaIdentityListType10(NasBuffer &nasBuffer) const {
    size_t l = 0;
    while (l++ < m_partialTaiList.size()) {
      m_partialTaiList[l].EncodePLMN(nasBuffer);
      m_partialTaiList[l].EncodeTAC(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

public:

  size_t Size() const {
    size_t s = sizeof(uint8_t);
    if(m_ptaiListType == PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_00) {
      if(!m_partialTaiList.empty()) {
        s += m_partialTaiList[0].GetPlmnIdenity().Size();
        for(auto& it: m_partialTaiList) {
            s += it.GetTrackingAreaCode().Size();
        }
      }
    }
    else if(m_ptaiListType == PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_01) {
      if(!m_partialTaiList.empty()) {
        s += m_partialTaiList[0].GetPlmnIdenity().Size();
        s += m_partialTaiList[0].GetTrackingAreaCode().Size();
      }
    }
    else if(m_ptaiListType == PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_10) {
      if(!m_partialTaiList.empty()) {
        for(auto& it: m_partialTaiList) {
            s += it.GetPlmnIdenity().Size();
            s += it.GetTrackingAreaCode().Size();
        }
      }
    }
    return s;
  }
  NasCause Decode(const NasBuffer &nasBuffer) {
  
    uint8_t v = nasBuffer.DecodeU8();
    m_ptaiListType =
        static_cast<PartialTrackingAreaIdentityListType>((v & 0b01100000) >> 5);      
    size_t taiListSize = static_cast<size_t>(v & 0b00011111) + 1;

    switch (m_ptaiListType) {
      case PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_00: {
        DecodePartialTrackingAreaIdentityListType00(nasBuffer, taiListSize);
        break;
      }
      case PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_01: {
        DecodePartialTrackingAreaIdentityListType01(nasBuffer, taiListSize);
        break;
      }
      case PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_10: {
        DecodePartialTrackingAreaIdentityListType10(nasBuffer, taiListSize);
        break;
      }
      default: {
        return NasCause::NAS_CAUSE_FAILURE;
        break;
      }
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer) const {
    uint8_t v = 0x0;
    v = ((static_cast<uint8_t>(m_ptaiListType) & 0x00000011) << 5);
    v = v | ((static_cast<uint8_t>(m_partialTaiList.size()-1)) & 0x00011111);
    nasBuffer.EncodeU8(v);

    switch (m_ptaiListType) {
      case PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_00: {
        EncodePartialTrackingAreaIdentityListType00(nasBuffer);
        break;
      }
      case PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_01: {
        EncodePartialTrackingAreaIdentityListType01(nasBuffer);
        break;
      }
      case PartialTrackingAreaIdentityListType::PTAI_LIST_TYPE_10: {
        EncodePartialTrackingAreaIdentityListType10(nasBuffer);
        break;
      }
      default: {
        return NasCause::NAS_CAUSE_FAILURE;
        break;
      }
    }
    return NasCause::NAS_CAUSE_SUCCESS;    
  }

};

class FiveGsTrackingAreaIdentityListIE : public InformationElement {
private:
  std::vector<PartialTrackingAreaIdentityList> m_partialTaiList;

public:
  size_t Size() const override { 
    return 0;}

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY_LIST;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t l = nasBuffer.DecodeU8();
    uint8_t size = 0;
    while(size < l) {
       PartialTrackingAreaIdentityList taiList;
       taiList.Decode(nasBuffer);
       size += taiList.Size();
       m_partialTaiList.emplace_back(taiList);
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    size_t l = 0;
    for(auto& it: m_partialTaiList) {
       l += it.Size(); 
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(l));
    for(auto& it: m_partialTaiList) {
       it.Encode(nasBuffer); 
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class FiveGsUpdateTypeIE : public InformationElement {
  uint8_t m_octet1 = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_UPDATE_TYPE;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (0x1 == l) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_octet1 = nasBuffer.DecodeU8();

    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (0x0 == m_octet1) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x1);
    nasBuffer.EncodeU8(m_octet1);

    return NasCause::NAS_CAUSE_SUCCESS;
  }

  bool isSmsRequested() const { return NasUtils::getBit(m_octet1, 1); }

  void setSmsRequested() { NasUtils::setBit(m_octet1, 1); }

  bool isNgranRadioCapabilityUpdate() const {
    return NasUtils::getBit(m_octet1, 2);
  }

  void setNgranRadioCapabilityUpdate() { NasUtils::setBit(m_octet1, 2); }

  FiveGSPreferredCIoTNetworkBehaviour getFiveGsPnbCIoT() const {
    return static_cast<FiveGSPreferredCIoTNetworkBehaviour>(
        (m_octet1 & 0b00001100) >> 2);
  }

  void setFiveGsPnbCIoT(FiveGSPreferredCIoTNetworkBehaviour mFiveGsPnbCIoT) {
    m_octet1 = (m_octet1 & 0b11110011) |
               (((static_cast<uint8_t>(mFiveGsPnbCIoT)) & 0b00000011) << 2);
  }

  EPSPreferredCIoTNetworkBehaviour getEpsPnbCIoT() const {
    return static_cast<EPSPreferredCIoTNetworkBehaviour>(
        (m_octet1 & 0b00110000) >> 4);
  }

  void setEpsPnbCIoT(EPSPreferredCIoTNetworkBehaviour mEpsPnbCIoT) {
    m_octet1 = (m_octet1 & 0b11001111) |
               (((static_cast<uint8_t>(mEpsPnbCIoT)) & 0b00000011) << 4);
  }
};

class AbbaIE : public InformationElement {
private:
  std::vector<uint8_t> m_abba;

public:
  void SetAbba(std::vector<uint8_t> &abba) { m_abba = abba; }
  std::vector<uint8_t> GetAbba() const { return m_abba; }

  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ABBA;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_abba, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_abba.size()));
    nasBuffer.EncodeU8Vector(m_abba);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class Additional5GSecurityInformationIE : public InformationElement {
  uint8_t m_additional5GSecurity = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ADDITIONAL_5G_SECURITY_INFORMATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_additional5GSecurity = nasBuffer.DecodeU8();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_additional5GSecurity);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AdditionalInformationRequestedIE : public InformationElement {
  uint8_t m_additionalInfoRequested = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ADDITIONAL_INFORMATION_REQUESTED;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_additionalInfoRequested = nasBuffer.DecodeU8();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_additionalInfoRequested);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AllowedPduSessionStatusIE : public InformationElement {
  uint8_t m_octet1 = 0x0;
  uint8_t m_octet2 = 0x0;
  std::vector<uint8_t> m_allowedPDUStatus;

public:
  size_t Size() const override { return m_allowedPDUStatus.size() + 2; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ALLOWED_PDU_SESSION_STATUS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    m_octet1 = nasBuffer.DecodeU8();
    m_octet2 = nasBuffer.DecodeU8();
    if (l > 0x2) {
      return nasBuffer.DecodeU8Vector(m_allowedPDUStatus, l - 2);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(Size()));
    nasBuffer.EncodeU8(m_octet1);
    nasBuffer.EncodeU8(m_octet2);
    nasBuffer.EncodeU8Vector(m_allowedPDUStatus);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AuthenticationFailureParameterIE : public InformationElement {
private:
  std::vector<uint8_t> m_authFailureParameter;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_AUTHENTICATION_FAILURE_PARAMETER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_authFailureParameter, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_authFailureParameter.size()));
    nasBuffer.EncodeU8Vector(m_authFailureParameter);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AuthenticationParameterAutnIE : public InformationElement {
private:
  std::vector<uint8_t> m_authenticatonParameterAutn;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_AUTHENTICATION_PARAMETER_AUTN;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_authenticatonParameterAutn, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(
        static_cast<uint8_t>(m_authenticatonParameterAutn.size()));
    nasBuffer.EncodeU8Vector(m_authenticatonParameterAutn);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AuthenticationParameterRandIE : public InformationElement {
private:
  std::vector<uint8_t> m_authenticationParameterRand;

public:
  void
  SetAuthenticationParameterRand(const std::vector<uint8_t> &authParamRand) {
    m_authenticationParameterRand = authParamRand;
  }
  std::vector<uint8_t> GetAuthenticationParameterRand() const {
    return m_authenticationParameterRand;
  }

  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_AUTHENTICATION_PARAMETER_RAND;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    return nasBuffer.DecodeU8Vector(m_authenticationParameterRand,
                                    AUTHENTICATION_PARAM_RAND_SIZE);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8Vector(m_authenticationParameterRand);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AuthenticationResponseParameterIE : public InformationElement {
private:
  std::vector<uint8_t> m_authResponseParameter;

public:
  size_t Size() const override { return m_authResponseParameter.size(); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_AUTHENTICATION_RESPONSE_PARAMETER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_authResponseParameter, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_authResponseParameter.size()));
    nasBuffer.EncodeU8Vector(m_authResponseParameter);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ConfigurationUpdateIndicationIE : public InformationElement {
  bool m_ackRequested = false;
  bool m_registrationRequested = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_CONFIGURATION_UPDATE_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = nasBuffer.DecodeNibble();
    m_ackRequested = static_cast<bool>(v & 0x1);
    m_registrationRequested = static_cast<bool>((v & 0x2) >> 1);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = 0x0;
    v = (v & (static_cast<uint8_t>(m_ackRequested) & 0x1));
    v = ((v & 0x1) | (static_cast<uint8_t>(m_registrationRequested) & 0x2));
    nasBuffer.EncodeNibble(v);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class CAGEntry {
private:
  PlmnIdentity m_plmnIdentity;
  bool m_cagOnly = false;
  std::vector<uint32_t> m_cagIdList;

public:
  size_t Size() const { return m_cagIdList.size() + 4; }

  NasCause Decode(const NasBuffer &nasBuffer) {
    uint8_t el = nasBuffer.DecodeU8();

    if (nasBuffer.IsBufferExceeds(el)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    m_plmnIdentity.Decode(nasBuffer);
    m_cagOnly = static_cast<bool>(nasBuffer.DecodeU8() & 0x1);

    for (uint8_t index = 4; index < el; ++index) {
      m_cagIdList.emplace_back(nasBuffer.DecodeU32());
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const {

    nasBuffer.EncodeU8(static_cast<uint8_t>(Size()));

    m_plmnIdentity.Encode(nasBuffer);

    nasBuffer.EncodeU8(static_cast<uint8_t>(m_cagOnly));

    for (auto it : m_cagIdList) {
      nasBuffer.EncodeU32(it);
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class CagInformationListIE : public InformationElement {
private:
  std::vector<CAGEntry> m_cagEntryList;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_CAG_INFORMATION_LIST;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    if (nasBuffer.IsBufferExceeds(l)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t index = 0;
    while (index < l) {
      CAGEntry entry;
      entry.Decode(nasBuffer);
      m_cagEntryList.emplace_back(entry);
      index += entry.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = 0;
    for (auto entry : m_cagEntryList) {
      l += entry.Size();
    }
    nasBuffer.EncodeU16(l);
    for (auto entry : m_cagEntryList) {
      entry.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class CiotSmallDataContainerIE : public InformationElement {
private:
  CIoTSmallDataContainerDataType m_dataType =
      CIoTSmallDataContainerDataType::CONTROL_PLANE_USERDATA;
  DownlinkDataExpected m_ddx = DownlinkDataExpected::NO_INFORMATION;
  PduSessionIdentityVal m_pduSessionId = PduSessionIdentityVal::NO_VAL;
  std::vector<uint8_t> m_dataContents;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_CIOT_SMALL_DATA_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (nasBuffer.IsBufferExceeds(l)) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = nasBuffer.DecodeU8();
    m_dataType =
        static_cast<CIoTSmallDataContainerDataType>((v & 0b11100000) >> 5);
    if (m_dataType == CIoTSmallDataContainerDataType::CONTROL_PLANE_USERDATA) {
      m_pduSessionId = static_cast<PduSessionIdentityVal>(v & 0b111);
      m_ddx = static_cast<DownlinkDataExpected>((v & 0b00011000) >> 3);
    } else if (m_dataType == CIoTSmallDataContainerDataType::SMS) {
      m_ddx = static_cast<DownlinkDataExpected>((v & 0b00011000) >> 3);
    } else {
    }
    return nasBuffer.DecodeU8Vector(m_dataContents, l - 1);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    nasBuffer.EncodeU8(static_cast<uint8_t>(m_dataContents.size() + 1));

    uint8_t v = 0x0;
    v = (((static_cast<uint8_t>(m_dataType)) & 0b00000111) << 5);

    if (m_dataType == CIoTSmallDataContainerDataType::CONTROL_PLANE_USERDATA) {
      v = ((v & 0b11111000) |
           ((static_cast<uint8_t>(m_pduSessionId)) & 0b00000111));
      v = (v & 0b11100111) | (((static_cast<uint8_t>(m_ddx)) & 0x2) << 3);
    } else if (m_dataType == CIoTSmallDataContainerDataType::SMS) {
      v = (v & 0b11100111) | (((static_cast<uint8_t>(m_ddx)) & 0x2) << 3);
    } else {
    }
    nasBuffer.EncodeU8(v);

    nasBuffer.EncodeU8Vector(m_dataContents);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class CiperingDataSet {
private:
  uint16_t m_ciperingSetID = 0;
  std::vector<uint8_t> m_ciperingKey;
  std::vector<uint8_t> m_c0;
  std::vector<uint8_t> m_eUtraPosSIB;
  std::vector<uint8_t> m_nRPosSIB;
  std::vector<uint8_t> m_validityStartTime;
  uint16_t m_validityDuration = 0;
  FiveGsTrackingAreaIdentityListIE m_taiList;

public:
  NasCause Decode(const NasBuffer &nasBuffer) {
    m_ciperingSetID = nasBuffer.DecodeU16();

    if (NasCause::NAS_CAUSE_FAILURE ==
        nasBuffer.DecodeU8Vector(m_ciperingKey, 16))
      return NasCause::NAS_CAUSE_FAILURE;

    uint8_t c0l = (nasBuffer.DecodeU8() & 0b00011111);
    if (NasCause::NAS_CAUSE_FAILURE == nasBuffer.DecodeU8Vector(m_c0, c0l))
      return NasCause::NAS_CAUSE_FAILURE;

    uint8_t el = (nasBuffer.DecodeU8() & 0b00001111);
    if (NasCause::NAS_CAUSE_FAILURE ==
        nasBuffer.DecodeU8Vector(m_eUtraPosSIB, el))
      return NasCause::NAS_CAUSE_FAILURE;

    uint8_t nl = (nasBuffer.DecodeU8() & 0b00001111);
    if (NasCause::NAS_CAUSE_FAILURE ==
        nasBuffer.DecodeU8Vector(m_eUtraPosSIB, nl))
      return NasCause::NAS_CAUSE_FAILURE;

    m_taiList.Decode(nasBuffer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const {

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};
class CipheringKeyDataIE : public InformationElement {
  std::vector<CiperingDataSet> m_ciperingDataSet;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_CIPHERING_KEY_DATA;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ControlPlaneServiceTypeIE : public InformationElement {
  ControlPlaneServiceType m_cpst = ControlPlaneServiceType::MOBILE_ORIG_REQUEST;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_CONTROL_PLANE_SERVICE_TYPE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = nasBuffer.DecodeNibble();
    m_cpst = static_cast<ControlPlaneServiceType>(v & 0x3);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t v = 0x0;
    v = (v & (static_cast<uint8_t>(m_cpst) & 0x3));
    nasBuffer.EncodeNibble(v);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class DaylightSavingTimeIE : public InformationElement {
  DaylightSavingTime m_dayLightSavingTime = DaylightSavingTime::NO_ADJUSTMENT;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_DAYLIGHT_SAVING_TIME;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (nasBuffer.DecodeU8() != 0x0) {
      m_dayLightSavingTime =
          static_cast<DaylightSavingTime>(nasBuffer.DecodeU8() & 0x2);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x1);
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_dayLightSavingTime) & 0x2);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class NetworkDaylightSavingTimeIE : public DaylightSavingTimeIE {
public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NETWORK_DAYLIGHT_SAVING_TIME;
  }
};

class DeRegistrationTypeIE : public InformationElement {
  bool m_swithedoff = false;
  bool m_reRegistrationRequired = false;
  AccessType m_accessType = AccessType::THREEGPP_ACCESS;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_DEREGISTRATION_TYPE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = nasBuffer.DecodeNibble();
    m_swithedoff = NasUtils::getBit(v, 4);
    m_reRegistrationRequired = NasUtils::getBit(v, 3);
    m_accessType = static_cast<AccessType>(v & 0x2);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t v = 0x0;
    if (m_swithedoff) {
      NasUtils::setBit(v, 4);
    }
    if (m_reRegistrationRequired) {
      NasUtils::setBit(v, 3);
    }
    v = v | (static_cast<uint8_t>(m_accessType) & 0x2);

    nasBuffer.EncodeNibble(v);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EmergencyNumberInformation {
private:
  uint8_t m_emergencyServiceCategory = 0x0;
  std::vector<uint8_t> m_emergencyNumber;

public:
  virtual size_t GetEmergencyNumberInformationSize() {
    return m_emergencyNumber.size() + 2;
  }

  virtual NasCause Decode(const NasBuffer &nasBuffer) {

    uint8_t l = nasBuffer.DecodeU8();
    m_emergencyServiceCategory = nasBuffer.DecodeU8() & 0b00011111;
    return nasBuffer.DecodeU8Vector(m_emergencyNumber, l - 1);
  }
  virtual NasCause Encode(NasBuffer &nasBuffer) const {

    nasBuffer.EncodeU8(static_cast<uint8_t>(m_emergencyNumber.size() + 1));
    nasBuffer.EncodeU8(
        static_cast<uint8_t>(m_emergencyServiceCategory & 0b00011111));
    nasBuffer.EncodeU8Vector(m_emergencyNumber);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EmergencyNumberListIE : public InformationElement {
private:
  std::vector<EmergencyNumberInformation> m_emergencyNumberInfoList;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EMERGENCY_NUMBER_LIST;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    uint8_t index = 0x0;
    while (index < l) {
      EmergencyNumberInformation eni;
      eni.Decode(nasBuffer);
      m_emergencyNumberInfoList.emplace_back(eni);
      index += eni.GetEmergencyNumberInformationSize();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = 0;
    for (auto it : m_emergencyNumberInfoList) {
      l += it.GetEmergencyNumberInformationSize();
    }
    nasBuffer.EncodeU8(l);
    for (auto it : m_emergencyNumberInfoList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EpsBearerContextStatusIE : public InformationElement {
private:
  uint8_t m_octet1 = 0x0;
  uint8_t m_octet2 = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EPS_BEARER_CONTEXT_STATUS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (nasBuffer.DecodeU8() == 0x2) {
      m_octet1 = nasBuffer.DecodeU8();
      m_octet2 = nasBuffer.DecodeU8();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x2);
    nasBuffer.EncodeU8(m_octet1);
    nasBuffer.EncodeU8(m_octet2);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EpsNasMessageContainerIE : public InformationElement {
  std::vector<uint8_t> m_containerContents;

public:
  size_t Size() const override { return m_containerContents.size(); }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EPS_NAS_MESSAGE_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    return nasBuffer.DecodeU8Vector(m_containerContents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU16(static_cast<uint16_t>(m_containerContents.size()));
    nasBuffer.EncodeU8Vector(m_containerContents);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EpsNasSecurityAlgorithmsIE : public InformationElement {

  EpsTypeOfCipheringAlgorithm m_ciperingAlg = EpsTypeOfCipheringAlgorithm::EEA0;
  EpsTypeOfIntegrityProtectionAlgorithm m_integrityAlg =
      EpsTypeOfIntegrityProtectionAlgorithm::EIA0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EPS_NAS_SECURITY_ALGORITHMS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t v = nasBuffer.DecodeU8();
    m_ciperingAlg =
        static_cast<EpsTypeOfCipheringAlgorithm>((v & 0b01110000) >> 4);
    m_integrityAlg =
        static_cast<EpsTypeOfIntegrityProtectionAlgorithm>(v & 0b00000111);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = 0x0;
    v = static_cast<uint8_t>(m_integrityAlg) & 0b00000111;
    v = (v & 0b00001111) | ((static_cast<uint8_t>(m_ciperingAlg) & 0x0F) << 4);
    nasBuffer.EncodeU8(v);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SelectedEpsNasSecurityAlgorithmsIE : public EpsNasSecurityAlgorithmsIE {
public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SELECTED_EPS_NAS_SECURITY_ALGORITHMS;
  }
};

class ExtendedEmergencyNumber : public EmergencyNumberInformation {
private:
  std::vector<uint8_t> m_subServiceField;

public:
  virtual size_t GetEmergencyNumberInformationSize() override {
    return GetEmergencyNumberInformationSize() + m_subServiceField.size();
  }

  NasCause Decode(const NasBuffer &nasBuffer) override {

    EmergencyNumberInformation::Decode(nasBuffer);
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_subServiceField, l);
  }

  NasCause Encode(NasBuffer &nasBuffer) const override {
    EmergencyNumberInformation::Encode(nasBuffer);
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_subServiceField.size()));
    nasBuffer.EncodeU8Vector(m_subServiceField);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ExtendedEmergencyNumberListIE : public InformationElement {
  std::vector<ExtendedEmergencyNumber> m_extendedEmergencyNumber;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EXTENDED_EMERGENCY_NUMBER_LIST;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    uint16_t index = 0;
    while (index < l) {
      ExtendedEmergencyNumber een;
      een.Decode(nasBuffer);
      m_extendedEmergencyNumber.emplace_back(een);
      index += een.GetEmergencyNumberInformationSize();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = 0;
    for (auto it : m_extendedEmergencyNumber) {
      l += it.GetEmergencyNumberInformationSize();
    }
    nasBuffer.EncodeU16(l);

    for (auto it : m_extendedEmergencyNumber) {
      it.Encode(nasBuffer);
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ExtendedDrxParametersIE : public InformationElement {
  uint8_t m_pagingTimeWindow = 0x0;
  uint8_t m_eDRXValue = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EXTENDED_DRX_PARAMETERS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (nasBuffer.DecodeU8() == 0x1) {
      m_pagingTimeWindow = nasBuffer.DecodeNibble();
      m_eDRXValue = nasBuffer.DecodeNibble();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x1);
    nasBuffer.EncodeNibble(m_pagingTimeWindow);
    nasBuffer.EncodeNibble(m_eDRXValue);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ImeisvRequestIE : public InformationElement {
  ImeiSvRequest m_imeiSVRequested = ImeiSvRequest::NOT_REQUESTED;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_IMEISV_REQUEST;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_imeiSVRequested =
        static_cast<ImeiSvRequest>(nasBuffer.DecodeNibble() & 0x7);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_imeiSVRequested));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class LadnIndicationIE : public InformationElement {
private:
  std::vector<DnnIE> m_dnnList;

public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_LADN_INDICATION;
  }
  size_t Size() const {
    uint16_t l = 0;
    for (auto it : m_dnnList) {
      l += it.Size();
    }
    return l + 2;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    uint16_t index = 0;
    while (index < l) {
      DnnIE dnn;
      dnn.Decode(nasBuffer);
      m_dnnList.emplace_back(dnn);
      index += dnn.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = 0;
    for (auto it : m_dnnList) {
      l += it.Size();
    }
    nasBuffer.EncodeU16(l);
    for (auto it : m_dnnList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class LadnInformationIE : public InformationElement {
  std::vector<LadnIndicationIE> m_ladnList;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_LADN_INFORMATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    uint16_t index = 0;
    while (index < l) {
      LadnIndicationIE ldan;
      ldan.Decode(nasBuffer);
      m_ladnList.emplace_back(ldan);
      index += ldan.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = 0;
    for (auto it : m_ladnList) {
      l += it.Size();
    }
    nasBuffer.EncodeU16(l);
    for (auto it : m_ladnList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MicoIndicationIE : public InformationElement {
  bool m_raii = false;
  bool m_sprti = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_MICO_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = nasBuffer.DecodeNibble();
    m_raii = NasUtils::getBit(v, 1);
    m_sprti = NasUtils::getBit(v, 2);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = 0x0;
    if (m_raii)
      NasUtils::setBit(v, 1);
    if (m_sprti)
      NasUtils::setBit(v, 2);
    nasBuffer.EncodeNibble(v);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MaPduSessionInformationIE : public InformationElement {
  uint8_t m_maPDUSessionInfo = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_MA_PDU_SESSION_INFORMATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_maPDUSessionInfo = nasBuffer.DecodeNibble();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(m_maPDUSessionInfo);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MappedSNssai {
  std::vector<uint8_t> m_mappedSNssaiContent;
  public:
    NasCause Decode(const NasBuffer &nasBuffer)  {
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_mappedSNssaiContent, l);
  }

  NasCause Encode(NasBuffer &nasBuffer) const {

    nasBuffer.EncodeU8(static_cast<uint8_t>(m_mappedSNssaiContent.size()));
    nasBuffer.EncodeU8Vector(m_mappedSNssaiContent);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  size_t Size() const {
    return 0;
  }
};

class MappedNssaiIE : public InformationElement {
  std::vector<MappedSNssai> m_snnaiList;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_MAPPED_NSSAI;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    uint8_t index = 0;
    while (index < l) {
      SNssaiIE nssai;
      nssai.Decode(nasBuffer);
      index += nssai.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = 0;
    for (auto it : m_snnaiList) {
      l += it.Size();
    }
    nasBuffer.EncodeU8(l);
    for (auto it : m_snnaiList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MobileStationClassmark2IE : public InformationElement {
  std::vector<uint8_t> m_mobileStationClassMark2;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_MOBILE_STATION_CLASSMARK_2;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_mobileStationClassMark2, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_mobileStationClassMark2.size()));
    nasBuffer.EncodeU8Vector(m_mobileStationClassMark2);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class NasMessageContainerIE : public InformationElement {
  std::vector<uint8_t> m_containerContents;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NAS_MESSAGE_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    return nasBuffer.DecodeU8Vector(m_containerContents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = m_containerContents.size();
    nasBuffer.EncodeU16(l);
    nasBuffer.EncodeU8Vector(m_containerContents);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class NasSecurityAlgorithmsIE : public InformationElement {

  CipheringAlgorithmType m_ciperingAlg = CipheringAlgorithmType::EA0;
  IntegrityProtectionAlgorithmType m_integrityAlg =
      IntegrityProtectionAlgorithmType::IA0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NAS_SECURITY_ALGORITHMS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    m_ciperingAlg =
        static_cast<CipheringAlgorithmType>(nasBuffer.DecodeNibble());
    m_integrityAlg =
        static_cast<IntegrityProtectionAlgorithmType>(nasBuffer.DecodeNibble());

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_ciperingAlg));
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_integrityAlg));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SelectedNasSecurityAlgorithmsIE: public NasSecurityAlgorithmsIE {

  public:

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SELECTED_NAS_SECURITY_ALGORITHMS;
  }
};

class NetworkNameIE : public InformationElement {
  uint8_t m_numberOfSpareBitsInLastOctet = 0x0;
  bool m_addCI = false;
  CodingScheme m_codingScheme = CodingScheme::DEFAULT;
  std::vector<uint8_t> m_string;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NETWORK_NAME;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (l > 0) {
      uint8_t v = nasBuffer.DecodeU8();
      m_numberOfSpareBitsInLastOctet = v & 0x7;
      m_addCI = NasUtils::getBit(v, 4);
      m_codingScheme = static_cast<CodingScheme>((v & 0x70) >> 4);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_string.size() + 1));
    uint8_t v = 0x0;
    v = v & (static_cast<uint8_t>(m_codingScheme) << 4);
    v = (v & 0xF0) | (m_numberOfSpareBitsInLastOctet & 0x07);
    if (m_addCI) {
      NasUtils::setBit(v, 4);
    }
    nasBuffer.EncodeU8(v);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class FullNameOfNetworkIE: public NetworkNameIE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_FULL_NAME_OF_NETWORK;
  }
};

class ShortNameOfNetworkIE: public NetworkNameIE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SHORT_NAME_OF_NETWORK;
  }
};


class NetworkSlicingIndicationIE : public InformationElement {
  bool m_nssci = false;
  bool m_dcni = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NETWORK_SLICING_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = nasBuffer.DecodeNibble();
    m_nssci = NasUtils::getBit(v, 1);
    m_dcni = NasUtils::getBit(v, 2);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = 0x0;
    if (m_nssci) {
      NasUtils::setBit(v, 1);
    }
    if (m_dcni) {
      NasUtils::setBit(v, 2);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class Non3GppNwProvidedPoliciesIE : public InformationElement {
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NON_3GPP_NW_PROVIDED_POLICIES;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class Nssai : public InformationElement {
  std::vector<SNssaiIE> m_nssaiList;
  public:
    NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    uint8_t size = 0;
    while(size < l) {
      SNssaiIE s;
      s.Decode(nasBuffer);
      size += s.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t s = 0;
    for(auto it: m_nssaiList) {
      s += it.Size(); 
    }
    nasBuffer.EncodeU8(s);
    for(auto it: m_nssaiList) {
      it.Encode(nasBuffer); 
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  } 
};

class NssaiInclusionModeIE : public InformationElement {
  NssaiInclusionMode m_nssaiInclusionMode = NssaiInclusionMode::A;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NSSAI_INCLUSION_MODE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_nssaiInclusionMode =
        static_cast<NssaiInclusionMode>(nasBuffer.DecodeNibble());
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_nssaiInclusionMode));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class OperatorDefinedAccessCategoryDefinitionsIE : public InformationElement {
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::
        IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_FAILURE;
  }
};

class PayloadContainerIE : public InformationElement {
  std::vector<uint8_t> m_container;
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PAYLOAD_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    nasBuffer.DecodeU8Vector(m_container, l);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU16(static_cast<uint16_t>(m_container.size()));
    nasBuffer.EncodeU8Vector(m_container);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class PayloadContainerTypeIE : public InformationElement {
  PayloadContainerType m_payloadContainerType =
      PayloadContainerType::N1_SM_INFORMATION;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PAYLOAD_CONTAINER_TYPE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_payloadContainerType =
        static_cast<PayloadContainerType>(nasBuffer.DecodeNibble());
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_payloadContainerType));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class PduSessionIdentity2IE : public InformationElement {
  uint8_t m_pdusessionId2 = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PDU_SESSION_IDENTITY_2;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_pdusessionId2 = nasBuffer.DecodeU8();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_pdusessionId2);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};


class PduSessionIdIE : public PduSessionIdentity2IE {
  public:

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PDU_SESSION_ID;
  }
};


class OldPduSessionIdIE : public PduSessionIdentity2IE {
  public:

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_OLD_PDU_SESSION_ID;
  }
};

class PduSessionReactivationResultIE : public InformationElement {
  uint8_t m_octet1 = 0x0;
  uint8_t m_octet2 = 0x0;
  std::vector<uint8_t> m_spare;

public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT;
  }
  size_t Size() const { return m_spare.size() + 2; }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    m_octet1 = nasBuffer.DecodeU8();
    m_octet2 = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_spare, l - 2);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(Size()));
    nasBuffer.EncodeU8(m_octet1);
    nasBuffer.EncodeU8(m_octet2);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class PduSessionReactivationResultErrorCauseIE : public InformationElement {
private:
  std::vector<std::pair<PduSessionIdIE, FiveGmmCauseIE>>
      m_pduSessionReactiveError;

public:
  size_t Size() const { return m_pduSessionReactiveError.size() * 2; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::
        IE_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    for (uint16_t i = 0; i < l; i += 2) {
      PduSessionIdIE id;
      id.Decode(nasBuffer);
      FiveGmmCauseIE cause;
      cause.Decode(nasBuffer);
      m_pduSessionReactiveError.emplace_back(id, cause);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU16(static_cast<uint16_t>(Size()));
    for (auto it : m_pduSessionReactiveError) {
      it.first.Encode(nasBuffer);
      it.second.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class PduSessionStatusIE : public PduSessionReactivationResultIE {
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PDU_SESSION_STATUS;
  }
};

class PlmnListIE : public InformationElement {
  std::vector<PlmnIdentity> m_plmnList;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PLMN_LIST;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    for (uint8_t index = 0; index < l; index += 3) {
      PlmnIdentity plmn;
      plmn.Decode(nasBuffer);
      m_plmnList.emplace_back(plmn);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = 0x0;
    for (auto it : m_plmnList) {
      l += it.Size();
    }
    nasBuffer.EncodeU8(l);

    for (auto it : m_plmnList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EquivalentPlmnsIE: public PlmnListIE {
public:
    InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EQUIVALENT_PLMN_LIST;
  }
};

class RequestedNssaiIE : public SNssaiIE {

public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_REQUESTED_NSSAI;
  }

};

class AllowedNssaiIE : public SNssaiIE {

public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ALLOWED_NSSAI;
  }

};

class ConfiguredNssaiIE : public SNssaiIE {

public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_CONFIGURED_NSSAI;
  }

};

class RejectedNssai : public SNssaiIE {
private:
  RejectedSNssaiCause m_cause;
  std::vector<uint8_t> m_snssai;

public:
  size_t Size() const { return m_snssai.size() + sizeof(m_cause); }

  NasCause Decode(const NasBuffer &nasBuffer) {
    m_cause = static_cast<RejectedSNssaiCause>(nasBuffer.DecodeNibble());
    uint8_t l = nasBuffer.DecodeNibble();
    nasBuffer.DecodeU8Vector(m_snssai, l);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_cause));
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_snssai.size()));
    nasBuffer.EncodeU8Vector(m_snssai);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class RejectedNssaiIE : public InformationElement {
  std::vector<RejectedNssai> m_rejectedNssaiList;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_REJECTED_NSSAI;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    uint8_t index = 0;
    while (index < l) {
      RejectedNssai rejNssai;
      rejNssai.Decode(nasBuffer);
      m_rejectedNssaiList.emplace_back(rejNssai);
      index += rejNssai.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = 0x0;
    for (auto it : m_rejectedNssaiList) {
      l += it.Size();
    }
    nasBuffer.EncodeU8(l);
    for (auto it : m_rejectedNssaiList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ReleaseAssistanceIndicationIE : public InformationElement {
  DownlinkDataExpected m_ddx = DownlinkDataExpected::NO_INFORMATION;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_RELEASE_ASSISTANCE_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_ddx = static_cast<DownlinkDataExpected>(nasBuffer.DecodeNibble());

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_ddx));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class RequestTypeIE : public InformationElement {
  RequestType m_requestType = RequestType::INITIAL_REQUEST;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_REQUEST_TYPE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_requestType = static_cast<RequestType>(nasBuffer.DecodeNibble() & 0x7);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_requestType));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class S1UeNetworkCapabilityIE : public InformationElement {
  std::vector<uint8_t> m_capabilites;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_S1_UE_NETWORK_CAPABILITY;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_capabilites, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_capabilites.size());
    nasBuffer.EncodeU8Vector(m_capabilites);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class S1UeSecurityCapabilityIE : public InformationElement {
  std::vector<uint8_t> m_capabilites;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_S1_UE_SECURITY_CAPABILITY;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_capabilites, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_capabilites.size());
    nasBuffer.EncodeU8Vector(m_capabilites);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ReplayedS1UeSecurityCapabilityIE: public S1UeSecurityCapabilityIE {
public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_REPLAYED_S1_UE_SECURITY_CAPABILITY;
  }
};

class PartialServiceAreaIdentity {
private:
  PlmnIdentity m_plmnIdentity;
  std::vector<uint8_t> m_ServiceAreaCode;

public:
  NasCause DecodePLMN(const NasBuffer &nasBuffer) {
    m_plmnIdentity.Decode(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause DecodeSAC(const NasBuffer &nasBuffer) {
    return nasBuffer.DecodeU8Vector(m_ServiceAreaCode, 3);
  }

  NasCause EncodePLMN(NasBuffer &nasBuffer) const {

    m_plmnIdentity.Encode(nasBuffer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause EncodeSAC(NasBuffer &nasBuffer) const {
    nasBuffer.EncodeU8Vector(m_ServiceAreaCode);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  void clear() { m_ServiceAreaCode.clear(); }
};

class ServiceAreaListIE : public InformationElement {
private:
  bool m_allowedType = false;
  PartialServiceAreaIdentityListType m_ptaiListType =
      PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_00;
  std::vector<PartialServiceAreaIdentity> m_partialTaiList;

  NasCause
  DecodePartialServiceAreaIdentityListType00(const NasBuffer &nasBuffer,
                                             size_t taiListSize) {
    PartialServiceAreaIdentity partialTAI;
    partialTAI.DecodePLMN(nasBuffer);
    size_t l = 0;
    while (l < taiListSize) {
      partialTAI.DecodeSAC(nasBuffer);
      m_partialTaiList.emplace_back(partialTAI);
      partialTAI.clear();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause
  DecodePartialServiceAreaIdentityListType01(const NasBuffer &nasBuffer,
                                             size_t taiListSize) {

    PartialServiceAreaIdentity partialTAI;
    partialTAI.DecodePLMN(nasBuffer);
    partialTAI.DecodeSAC(nasBuffer);
    m_partialTaiList.emplace_back(partialTAI);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause
  DecodePartialServiceAreaIdentityListType10(const NasBuffer &nasBuffer,
                                             size_t taiListSize) {
    size_t l = 0;
    while (l < taiListSize) {
      PartialServiceAreaIdentity partialTAI;
      partialTAI.DecodePLMN(nasBuffer);
      partialTAI.DecodeSAC(nasBuffer);
      m_partialTaiList.emplace_back(partialTAI);
      partialTAI.clear();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause
  DecodePartialServiceAreaIdentityListType11(const NasBuffer &nasBuffer,
                                             size_t taiListSize) {

    PartialServiceAreaIdentity partialTAI;
    partialTAI.DecodePLMN(nasBuffer);
    m_partialTaiList.emplace_back(partialTAI);
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause
  EncodePartialServiceAreaIdentityListType00(NasBuffer &nasBuffer) const {
    m_partialTaiList[0].EncodePLMN(nasBuffer);
    size_t l = 0;
    while (l < m_partialTaiList.size()) {
      m_partialTaiList[l].EncodeSAC(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause
  EncodePartialServiceAreaIdentityListType01(NasBuffer &nasBuffer) const {
    m_partialTaiList[0].EncodePLMN(nasBuffer);
    m_partialTaiList[0].EncodeSAC(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause
  EncodePartialServiceAreaIdentityListType10(NasBuffer &nasBuffer) const {
    size_t l = 0;
    while (l < m_partialTaiList.size()) {
      m_partialTaiList[l].EncodePLMN(nasBuffer);
      m_partialTaiList[l].EncodeSAC(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause
  EncodePartialServiceAreaIdentityListType11(NasBuffer &nasBuffer) const {
    m_partialTaiList[0].EncodePLMN(nasBuffer);
    return NasCause::NAS_CAUSE_SUCCESS;
  }

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SERVICE_AREA_LIST;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t v = nasBuffer.DecodeU8();
    m_ptaiListType =
        static_cast<PartialServiceAreaIdentityListType>((v & 0b01100000) >> 5);
    size_t taiListSize = static_cast<size_t>(v & 0b00011111);

    switch (m_ptaiListType) {
    case PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_00: {
      DecodePartialServiceAreaIdentityListType00(nasBuffer, taiListSize);
      break;
    }
    case PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_01: {
      DecodePartialServiceAreaIdentityListType01(nasBuffer, taiListSize);
      break;
    }
    case PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_10: {
      DecodePartialServiceAreaIdentityListType10(nasBuffer, taiListSize);
      break;
    }
    case PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_11: {
      DecodePartialServiceAreaIdentityListType11(nasBuffer, taiListSize);
      break;
    }
    default: {
      return NasCause::NAS_CAUSE_FAILURE;
      break;
    }
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    uint8_t v = 0x0;
    v = ((static_cast<uint8_t>(m_ptaiListType) & 0x00000011) << 5);
    v = v | ((static_cast<uint8_t>(m_partialTaiList.size())) & 0x00011111);
    nasBuffer.EncodeU8(v);

    switch (m_ptaiListType) {
    case PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_00: {
      EncodePartialServiceAreaIdentityListType00(nasBuffer);
      break;
    }
    case PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_01: {
      EncodePartialServiceAreaIdentityListType01(nasBuffer);
      break;
    }
    case PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_10: {
      EncodePartialServiceAreaIdentityListType10(nasBuffer);
      break;
    }
    case PartialServiceAreaIdentityListType::PSERVICE_LIST_TYPE_11: {
      EncodePartialServiceAreaIdentityListType11(nasBuffer);
      break;
    }
    default: {
      return NasCause::NAS_CAUSE_FAILURE;
      break;
    }
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ServiceTypeIE : public InformationElement {
  ServiceType m_serviceType = ServiceType::SIGNALLING;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SERVICE_TYPE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_serviceType = static_cast<ServiceType>(nasBuffer.DecodeNibble() & 0x7);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_serviceType));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SmsIndicationIE : public InformationElement {
  bool m_smsAvailablityIndication = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SMS_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_smsAvailablityIndication =
        static_cast<bool>(nasBuffer.DecodeNibble() & 0x1);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_smsAvailablityIndication));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SorTransparentContainerIE : public InformationElement {
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SOR_TRANSPARENT_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SupportedCodecListIE : public InformationElement {
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SUPPORTED_CODEC_LIST;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class TimeZoneIE : public InformationElement {
  uint8_t m_timeZone = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_TIME_ZONE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_timeZone = nasBuffer.DecodeU8();
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_timeZone);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class LocalTimeZoneIE: public TimeZoneIE {
 public: 
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_LOCAL_TIME_ZONE;
  }
};

class TimeZoneAndTimeIE : public InformationElement {
  /*
  uint8_t m_year = 0x0;
  uint8_t m_month = 0x0;
  uint8_t m_day = 0x0;
  uint8_t m_hour = 0x0;
  uint8_t m_minute = 0x0;
  uint8_t m_second = 0x0;
  uint8_t m_timezone = 0x0;
 */
  std::vector<uint8_t> m_timezoneAndTime;
public:
  #define TIMEZONE_AND_TIME_LEN 7
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_TIME_ZONE_AND_TIME;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.DecodeU8Vector(m_timezoneAndTime, TIMEZONE_AND_TIME_LEN);
    /*
    m_year = nasBuffer.DecodeU8();
    m_month = nasBuffer.DecodeU8();
    m_day = nasBuffer.DecodeU8();
    m_hour = nasBuffer.DecodeU8();
    m_minute = nasBuffer.DecodeU8();
    m_second = nasBuffer.DecodeU8();
    m_timezone = nasBuffer.DecodeU8();
   */
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
/*
    nasBuffer.EncodeU8(m_year);
    nasBuffer.EncodeU8(m_month);
    nasBuffer.EncodeU8(m_day);
    nasBuffer.EncodeU8(m_hour);
    nasBuffer.EncodeU8(m_minute);
    nasBuffer.EncodeU8(m_second);
    nasBuffer.EncodeU8(m_timezone);
*/
    nasBuffer.EncodeU8Vector(m_timezoneAndTime);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class UniversalTimeAndLocalTimeZoneIE: public TimeZoneAndTimeIE {
 public: 
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_UINVERSAL_TIME_AND_LOCAL_TIME_ZONE;
  }
};


class UeParametersUpdateTransparentContainerIE : public InformationElement {
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::
        IE_UE_PARAMETERS_UPDATE_TRANSPARENT_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class UeSecurityCapabilityIE : public InformationElement {
  std::vector<uint8_t> m_capabilites;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_UE_SECURITY_CAPABILITY;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_capabilites, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_capabilites.size());
    nasBuffer.EncodeU8Vector(m_capabilites);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ReplayedUeSecurityCapabilityIE: public UeSecurityCapabilityIE {
public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_REPLAYED_UE_SECURITY_CAPABILITY;
  }
};


class UeUsageSettingIE : public InformationElement {
  bool m_isVoiceCentric = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_UE_USAGE_SETTING;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (nasBuffer.DecodeU8() == 0x1) {
      m_isVoiceCentric = static_cast<bool>(nasBuffer.DecodeU8() & 0x1);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x1);
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_isVoiceCentric));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class UeStatusIE : public InformationElement {
  bool m_isEmmRegistered = false;
  bool m_is5gmmRegistered = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_UE_STATUS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (nasBuffer.DecodeU8() == 0x1) {
      uint8_t v = nasBuffer.DecodeU8();
      m_isEmmRegistered = NasUtils::getBit(v, 1);
      m_is5gmmRegistered = NasUtils::getBit(v, 2);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x1);
    uint8_t v = 0x0;
    if (m_isEmmRegistered) {
      NasUtils::setBit(v, 1);
    }
    if (m_is5gmmRegistered) {
      NasUtils::setBit(v, 1);
    }
    nasBuffer.EncodeU8(v);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class UplinkDataStatusIE : public PduSessionStatusIE {
public:

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_UPLINK_DATA_STATUS;
  }
};

class UeRadioCapabilityIdIE : public InformationElement {
  std::vector<uint8_t> m_radioCapabilityId;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_UE_RADIO_CAPABILITY_ID;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    uint8_t index = 0;
    while (index < l) {
      m_radioCapabilityId.emplace_back(nasBuffer.DecodeNibble());
      m_radioCapabilityId.emplace_back(nasBuffer.DecodeNibble());
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    bool isOdd = false;
    if(m_radioCapabilityId.size() & 1) {
      isOdd = true;
    }

    if(isOdd) 
      nasBuffer.EncodeU8(static_cast<uint8_t>(m_radioCapabilityId.size()/2 + 1));
    else
      nasBuffer.EncodeU8(static_cast<uint8_t>(m_radioCapabilityId.size()/2));

    for(auto& it: m_radioCapabilityId) {
      nasBuffer.EncodeNibble(static_cast<uint8_t>(it));
    }
    if(isOdd) {
      nasBuffer.EncodeNibble(0x0F);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class UeRadioCapabilityIdDeletionIndicationIE : public InformationElement {
  uint8_t m_deletionIndicationRequest = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::
        IE_UE_RADIO_CAPABILITY_ID_DELETION_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_deletionIndicationRequest = nasBuffer.DecodeNibble() & 0x7;

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_deletionIndicationRequest));

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class Truncated5GSTmsiConfigurationIE : public InformationElement {
  uint8_t m_truncatedAmfSetId = 0x0;
  uint8_t m_truncatedAmfPointer = 0x0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_TRUNCATED_5G_S_TMSI_CONFIGURATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    if (nasBuffer.DecodeU8() == 0x1) {
      m_truncatedAmfSetId = nasBuffer.DecodeNibble();
      m_truncatedAmfPointer = nasBuffer.DecodeNibble();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x1);
    nasBuffer.EncodeNibble(m_truncatedAmfSetId);
    nasBuffer.EncodeNibble(m_truncatedAmfPointer);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class WusAssistanceInformationIE : public InformationElement {
  std::vector<uint8_t> m_wusAssistInformation;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_WUS_ASSISTANCE_INFORMATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_wusAssistInformation, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_wusAssistInformation.size());
    nasBuffer.EncodeU8Vector(m_wusAssistInformation);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class N5GcIndicationIE : public InformationElement {
public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_N5GC_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class NbN1ModeDrxParametersIE : public InformationElement {
private:
  NbN1ModeDrxValue m_drxParameters = NbN1ModeDrxValue::NOT_SPECIFIED;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_NB_N1_MODE_DRX_PARAMETERS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if(0x1 == l) {
      m_drxParameters = static_cast<NbN1ModeDrxValue>(nasBuffer.DecodeU8() & 0x0F);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(0x1));
    
    nasBuffer.EncodeU8(0x0F & static_cast<uint8_t>(m_drxParameters));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AdditionalConfigurationIndicationIE : public InformationElement {
  bool m_singallingConnectionMaintainRequest = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ADDITIONAL_CONFIGURATION_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_singallingConnectionMaintainRequest =
        static_cast<bool>(nasBuffer.DecodeNibble() & 0x1);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(
        static_cast<uint8_t>(m_singallingConnectionMaintainRequest));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class FiveGsmCapabilityIE : public InformationElement {
  std::vector<uint8_t> m_capabilites;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GSM_CAPABILITY;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_capabilites, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_capabilites.size());
    nasBuffer.EncodeU8Vector(m_capabilites);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class FiveGsmCauseIE : public InformationElement {
  FiveGsmCause m_cause = FiveGsmCause::CONDITIONAL_IE_ERROR;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GSM_CAUSE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_cause = static_cast<FiveGsmCause>(m_cause);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_cause));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AlwaysOnPduSessionIndicationIE : public InformationElement {
  bool m_alwaysOnPduSessionIndication = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ALWAYS_ON_PDU_SESSION_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_alwaysOnPduSessionIndication =
        static_cast<bool>(nasBuffer.DecodeNibble() & 0x1);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(
        static_cast<uint8_t>(m_alwaysOnPduSessionIndication));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AlwaysOnPduSessionRequestedIE : public InformationElement {
  bool m_alwaysOnPduSessionRequested = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ALWAYS_ON_PDU_SESSION_REQUESTED;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_alwaysOnPduSessionRequested =
        static_cast<bool>(nasBuffer.DecodeNibble() & 0x7);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_alwaysOnPduSessionRequested));

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AllowedSscModeIE : public InformationElement {
uint8_t m_allowdSscMode = 0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ALLOWED_SSC_MODE;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_allowdSscMode = nasBuffer.DecodeNibble();

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(m_allowdSscMode);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ProtocolIdentifer {
  uint16_t m_identifier = 0;
  std::vector<uint8_t> m_contents;

public:
  size_t Size() const { return m_contents.size() + 3; }

  NasCause Decode(const NasBuffer &nasBuffer) {
    m_identifier = nasBuffer.DecodeU16();
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_contents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    nasBuffer.EncodeU16(m_identifier);
    nasBuffer.EncodeU8(m_contents.size());
    nasBuffer.EncodeU8Vector(m_contents);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ExtendedProtocolConfigurationOptionsIE : public InformationElement {
  uint8_t m_configurationProtocol = 0x0;
  bool m_extension = false;
  std::vector<ProtocolIdentifer> m_protocolConfigurationOptions;

public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS;
  }

  size_t Size() const {
    uint8_t size = 0;
    for (auto it : m_protocolConfigurationOptions) {
      size += it.Size();
    }
    return size + 1;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    
    uint8_t v = nasBuffer.DecodeU8();
    m_configurationProtocol = v & 0x07;
    m_extension = (( v >> 7) & 1);

    uint16_t index = 0;
    while (index < l - 1) {
      ProtocolIdentifer identifer;
      identifer.Decode(nasBuffer);
      m_protocolConfigurationOptions.emplace_back(identifer);
      index += identifer.Size();
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    nasBuffer.EncodeU16(static_cast<uint16_t>(Size()));

    uint8_t v = 0;
    if(m_extension) {
      NasUtils::setBit(v, 8);  
    }
    v = ((v & 0xF0) | (m_configurationProtocol & 0x0F));
    nasBuffer.EncodeU8(v);

    for (auto it : m_protocolConfigurationOptions) {
      it.Encode(nasBuffer);
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class IntegrityProtectionMaximumDataRateIE : public InformationElement {
private:
  MaxDRPUIForDownlink m_mipd = MaxDRPUIForDownlink::NULL_NOTE;
  MaxDRPUIForUplink m_mipu = MaxDRPUIForUplink::NULL_NOTE;

public:
  IntegrityProtectionMaximumDataRateIE() {}

  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE;
  }
  void SetMaxDRPUIForDownlink(MaxDRPUIForDownlink mipd) { m_mipd = mipd; }
  MaxDRPUIForDownlink GetMaxDRPUIForDownlink() const { return m_mipd; }

  void SetMaxDRPUIForUplink(MaxDRPUIForUplink mipu) { m_mipu = mipu; }
  MaxDRPUIForUplink GetMaxDRPUIForUplink() const { return m_mipu; }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    m_mipd = static_cast<MaxDRPUIForDownlink>(nasBuffer.DecodeU8());
    m_mipu = static_cast<MaxDRPUIForUplink>(nasBuffer.DecodeU8());
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_mipd));
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_mipu));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EpsParameter {
  uint8_t m_epsParameterIdentifier = 0x0;
  std::vector<uint8_t> m_contents;

public:
  size_t Size() const { return m_contents.size() + 2; }

  NasCause Decode(const NasBuffer &nasBuffer) {
    m_epsParameterIdentifier = nasBuffer.DecodeU8();
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_contents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    nasBuffer.EncodeU8(m_epsParameterIdentifier);
    nasBuffer.EncodeU8(m_contents.size());
    nasBuffer.EncodeU8Vector(m_contents);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MappedEpsBearerContext {
  uint8_t m_epsBearerIdentity = 0x0;
  OperationCode m_operationCode = OperationCode::CREATE_NEW_EPS_BEARER;
  bool m_eBit = false;
  std::vector<EpsParameter> m_epsParameterList;

public:
  size_t Size() const {
    size_t size = 0;
    for (auto it : m_epsParameterList) {
      size += it.Size();
    }
    size += 3;
    return size;
  }
  NasCause Decode(const NasBuffer &nasBuffer) {
    m_epsBearerIdentity = nasBuffer.DecodeU8();

    uint8_t v = nasBuffer.DecodeU8();
    m_operationCode = static_cast<OperationCode>(((v & 0b11000000) >> 6));
    m_eBit = NasUtils::getBit(v, 5);

    uint8_t epsParametersList = (v & 0xF);
    for (uint8_t index = 0; index < epsParametersList; ++index) {
      EpsParameter epsParameter;
      epsParameter.Decode(nasBuffer);
      m_epsParameterList.emplace_back(epsParameter);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    nasBuffer.EncodeU8(m_epsBearerIdentity);

    uint8_t v = 0x0;
    v = (((static_cast<uint8_t>(m_operationCode)) & 0x3) << 6);
    if (m_eBit) {
      NasUtils::setBit(v, 5);
    }
    v = (v & 0xF0) | (m_epsParameterList.size() & 0xF);
    nasBuffer.EncodeU8(v);
    for (auto it : m_epsParameterList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MappedEpsBearerContextsIE : public InformationElement {
  std::vector<MappedEpsBearerContext> m_mappedBearerContextList;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    uint16_t index = 0;
    while (index < l) {
      MappedEpsBearerContext context;
      context.Decode(nasBuffer);
      m_mappedBearerContextList.emplace_back(context);
      index += context.Size();
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = 0;
    for (auto it : m_mappedBearerContextList) {
      l += it.Size();
    }
    nasBuffer.EncodeU16(l);
    for (auto it : m_mappedBearerContextList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class MaximumNumberOfSupportedPacketFiltersIE : public InformationElement {
  uint16_t m_maxNumberOfSupportedPacketFilters = 0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::
        IE_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t v = nasBuffer.DecodeU16();
    m_maxNumberOfSupportedPacketFilters = (v >> 5);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU16(m_maxNumberOfSupportedPacketFilters << 5);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class PduAddressIE : public InformationElement {
  PduSessionType m_pduSessionType = PduSessionType::IPV4;
  std::vector<uint8_t> m_pduAddress;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PDU_ADDRESS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();

    m_pduSessionType =
        static_cast<PduSessionType>((nasBuffer.DecodeU8() & 0x7));

    return nasBuffer.DecodeU8Vector(m_pduAddress, l - 1);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_pduAddress.size() + 1);
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_pduSessionType));
    nasBuffer.EncodeU8Vector(m_pduAddress);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class PduSessionTypeIE : public InformationElement {
  PduSessionType m_pduSessionType = PduSessionType::IPV4;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PDU_SESSION_TYPE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_pduSessionType =
        static_cast<PduSessionType>(nasBuffer.DecodeNibble() & 0x7);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_pduSessionType));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SelectedPduSessionTypeIE: public PduSessionTypeIE {
  public:
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SELECTED_PDU_SESSION_TYPE;
  }
};

class QosParameter {
  QosParameterIdentifier m_qosParameterIdentifier =
      QosParameterIdentifier::FIVEQI;
  std::vector<uint8_t> m_contents;

public:
  size_t Size() const { return m_contents.size() + 2; }

  NasCause Decode(const NasBuffer &nasBuffer) {
    m_qosParameterIdentifier =
        static_cast<QosParameterIdentifier>(nasBuffer.DecodeU8());
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_contents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_qosParameterIdentifier));
    nasBuffer.EncodeU8(m_contents.size());
    nasBuffer.EncodeU8Vector(m_contents);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class QoSFlowDescription {
  uint8_t m_qfi = 0x0;
  OperationCode m_operationCode = OperationCode::CREATE_NEW_EPS_BEARER;
  bool m_eBit = false;
  std::vector<QosParameter> m_qosParameterList;

public:
  size_t Size() const {
    size_t size = 0;
    for (auto it : m_qosParameterList) {
      size += it.Size();
    }
    size += 3;
    return size;
  }
  NasCause Decode(const NasBuffer &nasBuffer) {
    m_qfi = (nasBuffer.DecodeU8() & 0b00111111);

    uint8_t v = nasBuffer.DecodeU8();
    m_operationCode = static_cast<OperationCode>(((v & 0b11100000) >> 5));

    v = nasBuffer.DecodeU8();
    m_eBit = NasUtils::getBit(v, 7);
    uint8_t epsParametersList = (v & 0x00111111);
    for (uint8_t index = 0; index < epsParametersList; ++index) {
      QosParameter qosParameter;
      qosParameter.Decode(nasBuffer);
      m_qosParameterList.emplace_back(qosParameter);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    nasBuffer.EncodeU8(m_qfi);

    uint8_t v = 0x0;
    v = (((static_cast<uint8_t>(m_operationCode)) & 0x7) << 5);
    nasBuffer.EncodeU8(v);

    v = 0x0;
    if (m_eBit) {
      NasUtils::setBit(v, 7);
    }

    v = v | (m_qosParameterList.size() & 0b00111111);
    nasBuffer.EncodeU8(v);

    for (auto it : m_qosParameterList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class QosFlowDescriptionsIE : public InformationElement {
  std::vector<QoSFlowDescription> m_qosFlowDescriptionList;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_QOS_FLOW_DESCRIPTIONS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    uint16_t index = 0;
    while (index < l) {
      QoSFlowDescription qosDesc;
      qosDesc.Decode(nasBuffer);
      l += qosDesc.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = 0;
    for (auto it : m_qosFlowDescriptionList) {
      l += it.Size();
    }
    nasBuffer.EncodeU16(l);
    for (auto it : m_qosFlowDescriptionList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AuthorizedQosFlowDescriptionsIE : public QosFlowDescriptionsIE {
  public:
    InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS;
  }
};

class RequestedQosFlowDescriptionsIE : public QosFlowDescriptionsIE {
  public:
    InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_REQUESTED_QOS_FLOW_DESCRIPTIONS;
  }
};



class QoSPacketFilter {
  uint8_t m_qosPacketIdentifier = 0x0;
  QoSPacketFilterDirection m_direction = QoSPacketFilterDirection::DOWNLINK;
  std::vector<uint8_t> m_contents;

public:
  size_t Size() const { 
    size_t s = 0;
    s = sizeof(m_qosPacketIdentifier);
    if(m_contents.size()) {
      s += (1 + m_contents.size());
    }
    return s; 
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  QosRuleOperationCode operationCode) {
    uint8_t v = nasBuffer.DecodeU8();
    m_qosPacketIdentifier = (v & 0x0F);
    
    if (operationCode !=
        QosRuleOperationCode::
            MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS) {
      m_direction = static_cast<QoSPacketFilterDirection>((v & 0b00110000) >> 4);
      uint8_t l = nasBuffer.DecodeU8();
      return nasBuffer.DecodeU8Vector(m_contents, l);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  QosRuleOperationCode operationCode) const {
    uint8_t v = 0x0;
    v = m_qosPacketIdentifier;

    if (operationCode !=
        QosRuleOperationCode::
            MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS) {
      v = (v & 0x0F) | (((static_cast<uint8_t>(m_direction)) & 0x3) << 4);
      nasBuffer.EncodeU8(v);
      nasBuffer.EncodeU8(m_contents.size());
      nasBuffer.EncodeU8Vector(m_contents);
    }
    else { 
      nasBuffer.EncodeU8(v);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class QoSRule {
private:
  uint8_t m_qosRuleIdentifier = 0x0;
  QosRuleOperationCode m_qosRuleOperationCode =
      QosRuleOperationCode::CREATE_NEW_QOS_RULE;
  bool m_dqrBit = false;
  std::vector<QoSPacketFilter> m_qosFilters;
  uint8_t m_qosRulePrecedence = 0x0;
  uint8_t m_qfi = 0x0;
  bool m_segigation = false;

public:
  size_t Size() const {
    size_t size = 0;
    size = sizeof(m_qosRuleIdentifier) + 
    + 2  //length
    + 1 ;//Rule operation Code + number of filters
    for(auto& it: m_qosFilters) {
      size += it.Size();
    }
    if(m_qosRulePrecedence) {
      size += 1;
    }
    if(m_qfi) {
      size += 1;
    }
    return size;
  }

  NasCause Decode(const NasBuffer &nasBuffer) {
    m_qosRuleIdentifier = nasBuffer.DecodeU8();
    uint16_t l = nasBuffer.DecodeU16();

    uint8_t v = nasBuffer.DecodeU8();
    uint8_t numFilters = v & 0x0F;
    m_dqrBit = NasUtils::getBit(v, 5);
    m_qosRuleOperationCode =
        static_cast<QosRuleOperationCode>((v & 0b11100000) >> 5);

    uint16_t lRule = 1;
    uint8_t index = 0;

    while (index < numFilters) {
      QoSPacketFilter filter;
      filter.Decode(nasBuffer, m_qosRuleOperationCode);
      m_qosFilters.emplace_back(filter);
      index++;
      lRule += filter.Size();
    }
    if (lRule < l) {
      m_qosRulePrecedence = nasBuffer.DecodeU8();
      lRule += 1;
    }
    if (lRule < l) {
      v = nasBuffer.DecodeU8();
      m_qfi = (v & 0b00111111);
      m_segigation = NasUtils::getBit(v, 7);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    nasBuffer.EncodeU8(m_qosRuleIdentifier);
    nasBuffer.EncodeU16(Size()-3);

    uint8_t v = 0x00;
    v = (static_cast<uint8_t>(m_qosFilters.size()) & 0x0F);
    if (m_dqrBit)
      NasUtils::setBit(v, 5);
    v = (v) | (((static_cast<uint8_t>(m_qosRuleOperationCode)) & 0x07) << 5);
    nasBuffer.EncodeU8(v);

    for (auto& it : m_qosFilters) {
      it.Encode(nasBuffer, m_qosRuleOperationCode);
    }
    if(m_qosRulePrecedence)
      nasBuffer.EncodeU8(m_qosRulePrecedence);

    if(m_qfi) {
      v = 0x0;
      v = m_qfi & 0b00111111;
      if (m_segigation) {
        NasUtils::setBit(v, 7);
      }
      nasBuffer.EncodeU8(v);
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class QosRulesIE : public InformationElement {
  std::vector<QoSRule> m_qosRuleList;

public:
  size_t Size() const override { 
    size_t l = 0;
    for (auto it : m_qosRuleList) {
      l += it.Size();
    }  
    return l;
  }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_QOS_RULES;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();

    uint16_t index = 0;
    while (index < l) {
      QoSRule rule;
      rule.Decode(nasBuffer);
      m_qosRuleList.emplace_back(rule);
      index += rule.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }

    nasBuffer.EncodeU16(Size());
    for (auto it : m_qosRuleList) {
      it.Encode(nasBuffer);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class RequestedQosRulesIE : public QosRulesIE {
  public:
    InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_REQUESTED_QOS_RULES;
  }
};

class AuthorizedQosRulesIE : public QosRulesIE {
  public:
    InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_AUTHORIZED_QOS_RULES;
  }
};

class SessionAmbrIE : public InformationElement {
  UnitForSessionAmbr m_unitForDownlink = UnitForSessionAmbr::MULT_1Kbps;
  uint16_t m_downlink = 0;
  UnitForSessionAmbr m_unitForUplink = UnitForSessionAmbr::MULT_1Kbps;
  uint16_t m_uplink = 0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SESSION_AMBR;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if(l == 0x6) {
      m_unitForDownlink = static_cast<UnitForSessionAmbr>(nasBuffer.DecodeU8());
      m_downlink = nasBuffer.DecodeU16();
      m_unitForUplink = static_cast<UnitForSessionAmbr>(nasBuffer.DecodeU8());
      m_uplink = nasBuffer.DecodeU16();
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x6);
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_unitForDownlink));
    nasBuffer.EncodeU16(m_downlink);
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_unitForUplink));
    nasBuffer.EncodeU16(m_uplink);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SmPduDnRequestContainerIE : public InformationElement {
  std::vector<uint8_t> m_dnSpecificIdenity;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SM_PDU_DN_REQUEST_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_dnSpecificIdenity, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_dnSpecificIdenity.size());
    nasBuffer.EncodeU8Vector(m_dnSpecificIdenity);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SscModeIE : public InformationElement {
  SscMode m_sscMode = SscMode::SSC_MODE_1;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SSC_MODE;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_sscMode = static_cast<SscMode>(nasBuffer.DecodeNibble() & 0x7);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_sscMode));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class SelectedSscModeIE: public SscModeIE {
 public: 
  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SELECTED_SSC_MODE;
  }
};

class ReAttemptIndicatorIE : public InformationElement {
  bool m_ratc = false;
  bool m_eplmnc = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_RE_ATTEMPT_INDICATOR;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = nasBuffer.DecodeU8();
    m_ratc = NasUtils::getBit(v, 1);
    m_eplmnc = NasUtils::getBit(v, 2);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t v = 0x0;
    if (m_ratc) {
      NasUtils::setBit(v, 1);
    }
    if (m_eplmnc) {
      NasUtils::setBit(v, 2);
    }
    nasBuffer.EncodeU8(v);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};
/*
class FiveGsmNetworkFeatureSupportIE : public InformationElement {
  std::vector<uint8_t> m_featureSupport;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_featureSupport, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_featureSupport.size());
    nasBuffer.EncodeU8Vector(m_featureSupport);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};
*/
class ServingPlmnRateControlIE : public InformationElement {
  uint16_t m_servingPlmnRateControl = 0;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_SERVING_PLMN_RATE_CONTROL;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (l > 0x0) {
      m_servingPlmnRateControl = nasBuffer.DecodeU16();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x2);
    nasBuffer.EncodeU16(m_servingPlmnRateControl);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class FiveGsmCongestionReAttemptIndicatorIE : public InformationElement {
  bool m_allPlmnBackoffTimer = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (0x1 == l) {
      m_allPlmnBackoffTimer = static_cast<bool>(nasBuffer.DecodeU8() & 0x1);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x1);
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_allPlmnBackoffTimer));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AtsssParameter {
  uint8_t m_identifier = 0x0;
  std::vector<uint8_t> m_contents;

public:
  size_t Size() const { return m_contents.size() + 2; }

  NasCause Decode(const NasBuffer &nasBuffer) {
    m_identifier = (nasBuffer.DecodeU8());
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_contents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer) const {
    nasBuffer.EncodeU8(m_identifier);
    nasBuffer.EncodeU8(m_contents.size());
    nasBuffer.EncodeU8Vector(m_contents);
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class AtsssContainerIE : public InformationElement {
  std::vector<AtsssParameter> m_atsssContainer;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ATSSS_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    uint16_t index = 0;
    while (index < l) {
      AtsssParameter parameter;
      parameter.Decode(nasBuffer);
      m_atsssContainer.emplace_back(parameter);
      index = index + parameter.Size();
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = 0;
    for (auto it : m_atsssContainer) {
      l += it.Size();
    }
    nasBuffer.EncodeU16(l);
    for (auto it : m_atsssContainer) {
      it.Encode(nasBuffer);
    }

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class ControlPlaneOnlyIndicationIE : public InformationElement {
  bool m_cpoi = false;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_CONTROL_PLANE_ONLY_INDICATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    m_cpoi = static_cast<bool>(nasBuffer.DecodeNibble() & 0x1);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer, true))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeNibble(static_cast<uint8_t>(m_cpoi));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class IpHeaderCompressionConfigurationIE : public InformationElement {
  uint8_t m_rochProfiles = 0x0;
  uint16_t m_maxCid = 0;
  AdditionalIPHdrCompressionContextParameterType m_type =
      AdditionalIPHdrCompressionContextParameterType::ESP_IP_0X0003;
  std::vector<uint8_t> m_container;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_IP_HEADER_COMPRESSION_CONFIGURATION;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();

    m_rochProfiles = nasBuffer.DecodeU8();
    m_maxCid = nasBuffer.DecodeU16();
    if (l > 0x3) {
      m_type = static_cast<AdditionalIPHdrCompressionContextParameterType>(
          nasBuffer.DecodeU8());
      return nasBuffer.DecodeU8Vector(m_container, l - 4);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = 0;
    l = m_container.size() + 4;
    nasBuffer.EncodeU8(l);
    nasBuffer.EncodeU8(m_rochProfiles);
    nasBuffer.EncodeU16(m_maxCid);
    nasBuffer.EncodeU8Vector(m_container);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class DsTtEthernetPortMacAddressIE : public InformationElement {
  std::vector<uint8_t> m_contents;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_DS_TT_ETHERNET_PORT_MAC_ADDRESS;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_contents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_contents.size());
    nasBuffer.EncodeU8Vector(m_contents);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class UeDsTtResidenceTimeIE : public InformationElement {
  std::vector<uint8_t> m_contents;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_UE_DS_TT_RESIDENCE_TIME;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    return nasBuffer.DecodeU8Vector(m_contents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(m_contents.size());
    nasBuffer.EncodeU8Vector(m_contents);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class PortManagementInformationContainerIE : public InformationElement {
  std::vector<uint8_t> m_contents;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_PORT_MANAGEMENT_INFORMATION_CONTAINER;
  }
  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint16_t l = nasBuffer.DecodeU16();
    return nasBuffer.DecodeU8Vector(m_contents, l);
  }
  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {

    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU16(m_contents.size());
    nasBuffer.EncodeU8Vector(m_contents);

    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class EthernetHeaderCompressionConfigurationIE : public InformationElement {
  CIDFieldLength m_cidFieldLenth = CIDFieldLength::COMPRESSION_NOT_USED;

public:
  size_t Size() const override { return 0; }

  InformationElementType getInformationElementType() const override {
    return InformationElementType::IE_ETHERNET_HEADER_COMPRESSION_CONFIGURATION;
  }

  NasCause Decode(const NasBuffer &nasBuffer,
                  bool isOptional = false) override {
    if (isOptional && (!DecodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    uint8_t l = nasBuffer.DecodeU8();
    if (l == 0x1) {
      m_cidFieldLenth = static_cast<CIDFieldLength>(nasBuffer.DecodeU8() & 0x3);
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause Encode(NasBuffer &nasBuffer,
                  bool isOptional = false) const override {
    if (isOptional && (!EncodeIEType(nasBuffer))) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    nasBuffer.EncodeU8(0x1);
    nasBuffer.EncodeU8(static_cast<uint8_t>(m_cidFieldLenth));
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

class InformationElementFactory {
public:


  static std::shared_ptr<InformationElement>
  AllocInformationElement(InformationElementType type) {
    std::shared_ptr<InformationElement> pIEI;
    switch (type) {
    case InformationElementType::IE_EXTENDED_PROTOCOL_DISCRIMINATOR: {
      pIEI = std::make_shared<ExtendedProtocolDiscriminatorIE>();
      break;
    }
    case InformationElementType::IE_SECURITY_HEADER_TYPE: {
      pIEI = std::make_shared<SecurityHeaderTypeIE>();
      break;
    }
    case InformationElementType::IE_PDU_SESSION_ID: {
      pIEI = std::make_shared<PduSessionIdIE>();
      break;
    }
    case InformationElementType::IE_SPARE_HALF_OCTET: {
      pIEI = std::make_shared<SpareHalfOctetIE>();
      break;
    }
    case InformationElementType::IE_PROCEDURE_TRANSACTION_IDENTITY: {
      pIEI = std::make_shared<ProcedureTransactionIdentityIE>();
      break;
    }
    case InformationElementType::IE_MESSAGE_TYPE: {
      pIEI = std::make_shared<MessageTypeIE>();
      break;
    }
    case InformationElementType::IE_MESSAGE_AUTHENTICATION_CODE: {
      pIEI = std::make_shared<MessageAuthenticationCodeIE>();
      break;
    }
    case InformationElementType::IE_SEQUENCE_NUMBER: {
      pIEI = std::make_shared<SequenceNumberIE>();
      break;
    }
    case InformationElementType::IE_ADDITIONAL_INFORMATION: {
      pIEI = std::make_shared<AdditionalInformationIE>();
      break;
    }
    case InformationElementType::IE_ACCESS_TYPE: {
      pIEI = std::make_shared<AccessTypeIE>();
      break;
    }
    case InformationElementType::IE_DNN: {
      pIEI = std::make_shared<DnnIE>();
      break;
    }
    case InformationElementType::IE_EAP_MESSAGE: {
      pIEI = std::make_shared<EapMessageIE>();
      break;
    }
    case InformationElementType::IE_GPRS_TIMER: {
      pIEI = std::make_shared<GprsTimerIE>();
      break;
    }
    case InformationElementType::IE_GPRS_TIMER_2: {
      pIEI = std::make_shared<GprsTimer2IE>();
      break;
    }
    case InformationElementType::IE_GPRS_TIMER_3: {
      pIEI = std::make_shared<GprsTimer3IE>();
      break;
    }
    case InformationElementType::IE_INTRA_N1_MODE_NAS_TRANSPARENT_CONTAINER: {
      pIEI = std::make_shared<IntraN1ModeNasTransparentContainerIE>();
      break;
    }
    case InformationElementType::
        IE_N1_MODE_TO_S1_MODE_NAS_TRANSPARENT_CONTAINER: {
      pIEI = std::make_shared<N1ModeToS1ModeNasTransparentContainerIE>();
      break;
    }
    case InformationElementType::IE_S_NSSAI: {
      pIEI = std::make_shared<SNssaiIE>();
      break;
    }
    case InformationElementType::
        IE_S1_MODE_TO_N1_MODE_NAS_TRANSPARENT_CONTAINER: {
      pIEI = std::make_shared<S1ModeToN1ModeNasTransparentContainerIE>();
      break;
    }
    case InformationElementType::IE_5GMM_CAPABILITY: {
      pIEI = std::make_shared<FiveGmmCapabilityIE>();
      break;
    }
    case InformationElementType::IE_5GMM_CAUSE: {
      pIEI = std::make_shared<FiveGmmCauseIE>();
      break;
    }
    case InformationElementType::IE_5GS_DRX_PARAMETERS: {
      pIEI = std::make_shared<FiveGsDrxParametersIE>();
      break;
    }
    case InformationElementType::IE_5GS_IDENTITY_TYPE: {
      pIEI = std::make_shared<FiveGsIdentityTypeIE>();
      break;
    }
    case InformationElementType::IE_5GS_MOBILE_IDENTITY: {
      pIEI = std::make_shared<MobileIdentityIE>();
      break;
    }
    case InformationElementType::IE_5GS_NETWORK_FEATURE_SUPPORT: {
      pIEI = std::make_shared<FiveGsNetworkFeatureSupportIE>();
      break;
    }
    case InformationElementType::IE_5GS_REGISTRATION_RESULT: {
      pIEI = std::make_shared<FiveGsRegistrationResultIE>();
      break;
    }
    case InformationElementType::IE_5GS_REGISTRATION_TYPE: {
      pIEI = std::make_shared<FiveGSRegistrationTypeIE>();
      break;
    }
    case InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY: {
      pIEI = std::make_shared<FiveGsTrackingAreaIdentityIE>();
      break;
    }
    case InformationElementType::IE_5GS_TRACKING_AREA_IDENTITY_LIST: {
      pIEI = std::make_shared<FiveGsTrackingAreaIdentityListIE>();
      break;
    }
    case InformationElementType::IE_5GS_UPDATE_TYPE: {
      pIEI = std::make_shared<FiveGsUpdateTypeIE>();
      break;
    }
    case InformationElementType::IE_ABBA: {
      pIEI = std::make_shared<AbbaIE>();
      break;
    }
    case InformationElementType::IE_ADDITIONAL_5G_SECURITY_INFORMATION: {
      pIEI = std::make_shared<Additional5GSecurityInformationIE>();
      break;
    }
    case InformationElementType::IE_ADDITIONAL_INFORMATION_REQUESTED: {
      pIEI = std::make_shared<AdditionalInformationRequestedIE>();
      break;
    }
    case InformationElementType::IE_ALLOWED_PDU_SESSION_STATUS: {
      pIEI = std::make_shared<AllowedPduSessionStatusIE>();
      break;
    }
    case InformationElementType::IE_AUTHENTICATION_FAILURE_PARAMETER: {
      pIEI = std::make_shared<AuthenticationFailureParameterIE>();
      break;
    }
    case InformationElementType::IE_AUTHENTICATION_PARAMETER_AUTN: {
      pIEI = std::make_shared<AuthenticationParameterAutnIE>();
      break;
    }
    case InformationElementType::IE_AUTHENTICATION_PARAMETER_RAND: {
      pIEI = std::make_shared<AuthenticationParameterRandIE>();
      break;
    }
    case InformationElementType::IE_AUTHENTICATION_RESPONSE_PARAMETER: {
      pIEI = std::make_shared<AuthenticationResponseParameterIE>();
      break;
    }
    case InformationElementType::IE_CONFIGURATION_UPDATE_INDICATION: {
      pIEI = std::make_shared<ConfigurationUpdateIndicationIE>();
      break;
    }
    case InformationElementType::IE_CAG_INFORMATION_LIST: {
      pIEI = std::make_shared<CagInformationListIE>();
      break;
    }
    case InformationElementType::IE_CIOT_SMALL_DATA_CONTAINER: {
      pIEI = std::make_shared<CiotSmallDataContainerIE>();
      break;
    }
    case InformationElementType::IE_CIPHERING_KEY_DATA: {
      pIEI = std::make_shared<CipheringKeyDataIE>();
      break;
    }
    case InformationElementType::IE_CONTROL_PLANE_SERVICE_TYPE: {
      pIEI = std::make_shared<ControlPlaneServiceTypeIE>();
      break;
    }
    case InformationElementType::IE_DAYLIGHT_SAVING_TIME: {
      pIEI = std::make_shared<DaylightSavingTimeIE>();
      break;
    }
    case InformationElementType::IE_DEREGISTRATION_TYPE: {
      pIEI = std::make_shared<DeRegistrationTypeIE>();
      break;
    }
    case InformationElementType::IE_EMERGENCY_NUMBER_LIST: {
      pIEI = std::make_shared<EmergencyNumberListIE>();
      break;
    }
    case InformationElementType::IE_EPS_BEARER_CONTEXT_STATUS: {
      pIEI = std::make_shared<EpsBearerContextStatusIE>();
      break;
    }
    case InformationElementType::IE_EPS_NAS_MESSAGE_CONTAINER: {
      pIEI = std::make_shared<EpsNasMessageContainerIE>();
      break;
    }
    case InformationElementType::IE_EPS_NAS_SECURITY_ALGORITHMS: {
      pIEI = std::make_shared<EpsNasSecurityAlgorithmsIE>();
      break;
    }
    case InformationElementType::IE_EXTENDED_EMERGENCY_NUMBER_LIST: {
      pIEI = std::make_shared<ExtendedEmergencyNumberListIE>();
      break;
    }
    case InformationElementType::IE_EXTENDED_DRX_PARAMETERS: {
      pIEI = std::make_shared<ExtendedDrxParametersIE>();
      break;
    }
    case InformationElementType::IE_IMEISV_REQUEST: {
      pIEI = std::make_shared<ImeisvRequestIE>();
      break;
    }
    case InformationElementType::IE_LADN_INDICATION: {
      pIEI = std::make_shared<LadnIndicationIE>();
      break;
    }
    case InformationElementType::IE_LADN_INFORMATION: {
      pIEI = std::make_shared<LadnInformationIE>();
      break;
    }
    case InformationElementType::IE_MICO_INDICATION: {
      pIEI = std::make_shared<MicoIndicationIE>();
      break;
    }
    case InformationElementType::IE_MA_PDU_SESSION_INFORMATION: {
      pIEI = std::make_shared<MaPduSessionInformationIE>();
      break;
    }
    case InformationElementType::IE_MAPPED_NSSAI: {
      pIEI = std::make_shared<MappedNssaiIE>();
      break;
    }
    case InformationElementType::IE_MOBILE_STATION_CLASSMARK_2: {
      pIEI = std::make_shared<MobileStationClassmark2IE>();
      break;
    }
    case InformationElementType::IE_NAS_KEY_SET_IDENTIFIER: {
      pIEI = std::make_shared<NasKeySetIdentifierIE>();
      break;
    }
    case InformationElementType::IE_NAS_MESSAGE_CONTAINER: {
      pIEI = std::make_shared<NasMessageContainerIE>();
      break;
    }
    case InformationElementType::IE_NAS_SECURITY_ALGORITHMS: {
      pIEI = std::make_shared<NasSecurityAlgorithmsIE>();
      break;
    }
    case InformationElementType::IE_SELECTED_NAS_SECURITY_ALGORITHMS: {
      pIEI = std::make_shared<SelectedNasSecurityAlgorithmsIE>();
      break;
    }
    case InformationElementType::IE_NETWORK_NAME: {
      pIEI = std::make_shared<NetworkNameIE>();
      break;
    }
    case InformationElementType::IE_NETWORK_SLICING_INDICATION: {
      pIEI = std::make_shared<NetworkSlicingIndicationIE>();
      break;
    }
    case InformationElementType::IE_NON_3GPP_NW_PROVIDED_POLICIES: {
      pIEI = std::make_shared<Non3GppNwProvidedPoliciesIE>();
      break;
    }
    case InformationElementType::IE_NSSAI: {
      pIEI = std::make_shared<SNssaiIE>();
      break;
    }
    case InformationElementType::IE_NSSAI_INCLUSION_MODE: {
      pIEI = std::make_shared<NssaiInclusionModeIE>();
      break;
    }
    case InformationElementType::
        IE_OPERATOR_DEFINED_ACCESS_CATEGORY_DEFINITIONS: {
      pIEI = std::make_shared<OperatorDefinedAccessCategoryDefinitionsIE>();
      break;
    }
    case InformationElementType::IE_PAYLOAD_CONTAINER: {
      pIEI = std::make_shared<PayloadContainerIE>();
      break;
    }
    case InformationElementType::IE_PAYLOAD_CONTAINER_TYPE: {
      pIEI = std::make_shared<PayloadContainerTypeIE>();
      break;
    }
    case InformationElementType::IE_PDU_SESSION_IDENTITY_2: {
      pIEI = std::make_shared<PduSessionIdentity2IE>();
      break;
    }
    case InformationElementType::IE_PDU_SESSION_REACTIVATION_RESULT: {
      pIEI = std::make_shared<PduSessionReactivationResultIE>();
      break;
    }
    case InformationElementType::
        IE_PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE: {
      pIEI = std::make_shared<PduSessionReactivationResultErrorCauseIE>();
      break;
    }
    case InformationElementType::IE_PDU_SESSION_STATUS: {
      pIEI = std::make_shared<PduSessionStatusIE>();
      break;
    }
    case InformationElementType::IE_PLMN_LIST: {
      pIEI = std::make_shared<PlmnListIE>();
      break;
    }
    case InformationElementType::IE_REJECTED_NSSAI: {
      pIEI = std::make_shared<RejectedNssaiIE>();
      break;
    }
    case InformationElementType::IE_RELEASE_ASSISTANCE_INDICATION: {
      pIEI = std::make_shared<ReleaseAssistanceIndicationIE>();
      break;
    }
    case InformationElementType::IE_REQUEST_TYPE: {
      pIEI = std::make_shared<RequestTypeIE>();
      break;
    }
    case InformationElementType::IE_S1_UE_NETWORK_CAPABILITY: {
      pIEI = std::make_shared<S1UeNetworkCapabilityIE>();
      break;
    }
    case InformationElementType::IE_S1_UE_SECURITY_CAPABILITY: {
      pIEI = std::make_shared<S1UeSecurityCapabilityIE>();
      break;
    }
    case InformationElementType::IE_SERVICE_AREA_LIST: {
      pIEI = std::make_shared<ServiceAreaListIE>();
      break;
    }
    case InformationElementType::IE_SERVICE_TYPE: {
      pIEI = std::make_shared<ServiceTypeIE>();
      break;
    }
    case InformationElementType::IE_SMS_INDICATION: {
      pIEI = std::make_shared<SmsIndicationIE>();
      break;
    }
    case InformationElementType::IE_SOR_TRANSPARENT_CONTAINER: {
      pIEI = std::make_shared<SorTransparentContainerIE>();
      break;
    }
    case InformationElementType::IE_SUPPORTED_CODEC_LIST: {
      pIEI = std::make_shared<SupportedCodecListIE>();
      break;
    }
    case InformationElementType::IE_TIME_ZONE: {
      pIEI = std::make_shared<TimeZoneIE>();
      break;
    }
    case InformationElementType::IE_TIME_ZONE_AND_TIME: {
      pIEI = std::make_shared<TimeZoneAndTimeIE>();
      break;
    }
    case InformationElementType::
        IE_UE_PARAMETERS_UPDATE_TRANSPARENT_CONTAINER: {
      pIEI = std::make_shared<UeParametersUpdateTransparentContainerIE>();
      break;
    }
    case InformationElementType::IE_UE_SECURITY_CAPABILITY: {
      pIEI = std::make_shared<UeSecurityCapabilityIE>();
      break;
    }
    case InformationElementType::IE_REPLAYED_UE_SECURITY_CAPABILITY: {
      pIEI = std::make_shared<ReplayedUeSecurityCapabilityIE>();
      break;
    }
    case InformationElementType::IE_UE_USAGE_SETTING: {
      pIEI = std::make_shared<UeUsageSettingIE>();
      break;
    }
    case InformationElementType::IE_UE_STATUS: {
      pIEI = std::make_shared<UeStatusIE>();
      break;
    }
    case InformationElementType::IE_UPLINK_DATA_STATUS: {
      pIEI = std::make_shared<UplinkDataStatusIE>();
      break;
    }
    case InformationElementType::IE_UE_RADIO_CAPABILITY_ID: {
      pIEI = std::make_shared<UeRadioCapabilityIdIE>();
      break;
    }
    case InformationElementType::
        IE_UE_RADIO_CAPABILITY_ID_DELETION_INDICATION: {
      pIEI = std::make_shared<UeRadioCapabilityIdDeletionIndicationIE>();
      break;
    }
    case InformationElementType::IE_TRUNCATED_5G_S_TMSI_CONFIGURATION: {
      pIEI = std::make_shared<Truncated5GSTmsiConfigurationIE>();
      break;
    }
    case InformationElementType::IE_WUS_ASSISTANCE_INFORMATION: {
      pIEI = std::make_shared<WusAssistanceInformationIE>();
      break;
    }
    case InformationElementType::IE_N5GC_INDICATION: {
      pIEI = std::make_shared<N5GcIndicationIE>();
      break;
    }
    case InformationElementType::IE_NB_N1_MODE_DRX_PARAMETERS: {
      pIEI = std::make_shared<NbN1ModeDrxParametersIE>();
      break;
    }
    case InformationElementType::IE_ADDITIONAL_CONFIGURATION_INDICATION: {
      pIEI = std::make_shared<AdditionalConfigurationIndicationIE>();
      break;
    }
    case InformationElementType::IE_5GSM_CAPABILITY: {
      pIEI = std::make_shared<FiveGsmCapabilityIE>();
      break;
    }
    case InformationElementType::IE_5GSM_CAUSE: {
      pIEI = std::make_shared<FiveGsmCauseIE>();
      break;
    }
    case InformationElementType::IE_ALWAYS_ON_PDU_SESSION_INDICATION: {
      pIEI = std::make_shared<AlwaysOnPduSessionIndicationIE>();
      break;
    }
    case InformationElementType::IE_ALWAYS_ON_PDU_SESSION_REQUESTED: {
      pIEI = std::make_shared<AlwaysOnPduSessionRequestedIE>();
      break;
    }
    case InformationElementType::IE_ALLOWED_SSC_MODE: {
      pIEI = std::make_shared<AllowedSscModeIE>();
      break;
    }
    case InformationElementType::IE_SELECTED_SSC_MODE: {
      pIEI = std::make_shared<SelectedSscModeIE>();
      break;
    }
    case InformationElementType::IE_EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS: {
      pIEI = std::make_shared<ExtendedProtocolConfigurationOptionsIE>();
      break;
    }
    case InformationElementType::IE_INTEGRITY_PROTECTION_MAXIMUM_DATA_RATE: {
      pIEI = std::make_shared<IntegrityProtectionMaximumDataRateIE>();
      break;
    }
    case InformationElementType::IE_MAPPED_EPS_BEARER_CONTEXTS: {
      pIEI = std::make_shared<MappedEpsBearerContextsIE>();
      break;
    }
    case InformationElementType::
        IE_MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS: {
      pIEI = std::make_shared<MaximumNumberOfSupportedPacketFiltersIE>();
      break;
    }
    case InformationElementType::IE_PDU_ADDRESS: {
      pIEI = std::make_shared<PduAddressIE>();
      break;
    }
    case InformationElementType::IE_PDU_SESSION_TYPE: {
      pIEI = std::make_shared<PduSessionTypeIE>();
      break;
    }
    case InformationElementType::IE_SELECTED_PDU_SESSION_TYPE: {
      pIEI = std::make_shared<SelectedPduSessionTypeIE>();
      break;
    }
    case InformationElementType::IE_QOS_FLOW_DESCRIPTIONS: {
      pIEI = std::make_shared<QosFlowDescriptionsIE>();
      break;
    }
    case InformationElementType::IE_QOS_RULES: {
      pIEI = std::make_shared<QosRulesIE>();
      break;
    }
    case InformationElementType::IE_SESSION_AMBR: {
      pIEI = std::make_shared<SessionAmbrIE>();
      break;
    }
    case InformationElementType::IE_SM_PDU_DN_REQUEST_CONTAINER: {
      pIEI = std::make_shared<SmPduDnRequestContainerIE>();
      break;
    }
    case InformationElementType::IE_SSC_MODE: {
      pIEI = std::make_shared<SscModeIE>();
      break;
    }
    case InformationElementType::IE_RE_ATTEMPT_INDICATOR: {
      pIEI = std::make_shared<ReAttemptIndicatorIE>();
      break;
    }
    // case InformationElementType::IE_5GSM_NETWORK_FEATURE_SUPPORT: {
    //   pIEI = std::make_shared<FiveGsmNetworkFeatureSupportIE>();
    //   break;
    // }
    case InformationElementType::IE_SERVING_PLMN_RATE_CONTROL: {
      pIEI = std::make_shared<ServingPlmnRateControlIE>();
      break;
    }
    case InformationElementType::IE_5GSM_CONGESTION_RE_ATTEMPT_INDICATOR: {
      pIEI = std::make_shared<FiveGsmCongestionReAttemptIndicatorIE>();
      break;
    }
    case InformationElementType::IE_ATSSS_CONTAINER: {
      pIEI = std::make_shared<AtsssContainerIE>();
      break;
    }
    case InformationElementType::IE_CONTROL_PLANE_ONLY_INDICATION: {
      pIEI = std::make_shared<ControlPlaneOnlyIndicationIE>();
      break;
    }
    case InformationElementType::IE_IP_HEADER_COMPRESSION_CONFIGURATION: {
      pIEI = std::make_shared<IpHeaderCompressionConfigurationIE>();
      break;
    }
    case InformationElementType::IE_DS_TT_ETHERNET_PORT_MAC_ADDRESS: {
      pIEI = std::make_shared<DsTtEthernetPortMacAddressIE>();
      break;
    }
    case InformationElementType::IE_UE_DS_TT_RESIDENCE_TIME: {
      pIEI = std::make_shared<UeDsTtResidenceTimeIE>();
      break;
    }
    case InformationElementType::IE_PORT_MANAGEMENT_INFORMATION_CONTAINER: {
      pIEI = std::make_shared<PortManagementInformationContainerIE>();
      break;
    }
    case InformationElementType::IE_ETHERNET_HEADER_COMPRESSION_CONFIGURATION: {
      pIEI = std::make_shared<EthernetHeaderCompressionConfigurationIE>();
      break;
    }
    case InformationElementType::IE_LAST_VISITED_REGISTERED_TRACKING_AREA_IDENTITY: {
      pIEI = std::make_shared<LastVisitedRegisteredTaiIE>();
    break;
    }
      case InformationElementType::IE_5G_GUTI: {
        pIEI = std::make_shared<FiveGGutiIE>();
    break;
    }
      case InformationElementType::IE_ADDITIONAL_GUTI: {
        pIEI = std::make_shared<AdditionalGutiIE>();
    break;
    }
      case InformationElementType::IE_ALLOWED_NSSAI: {
        pIEI = std::make_shared<AllowedNssaiIE>();
    break;
    }
      case InformationElementType::IE_AUTHORIZED_QOS_FLOW_DESCRIPTIONS: {
        pIEI = std::make_shared<AuthorizedQosFlowDescriptionsIE>();
    break;
    }
      case InformationElementType::IE_AUTHORIZED_QOS_RULES: {
        pIEI = std::make_shared<AuthorizedQosRulesIE>();
    break;
    }
      case InformationElementType::IE_BACK_OFF_TIMER_VALUE: {
        pIEI = std::make_shared<BackOffTimerValueIE>();
    break;
    }
      case InformationElementType::IE_CONFIGURED_NSSAI: {
        pIEI = std::make_shared<ConfiguredNssaiIE>();
    break;
    }
      case InformationElementType::IE_EQUIVALENT_PLMN_LIST: {
        pIEI = std::make_shared<EquivalentPlmnsIE>();
    break;
    }
      case InformationElementType::IE_FULL_NAME_OF_NETWORK: {
        pIEI = std::make_shared<FullNameOfNetworkIE>();
    break;
    }
      case InformationElementType::IE_IMEISV: {
        pIEI = std::make_shared<ImeiSvIE>();
    break;
    }
      case InformationElementType::IE_LOCAL_TIME_ZONE: {
        pIEI = std::make_shared<LocalTimeZoneIE>();
    break;
    }
    case InformationElementType::IE_NAS_KEY_SET_IDENTIFIER_1: {
      pIEI = std::make_shared<NasKeySetIdentifierIE>();
    break;
    }
    case InformationElementType::IE_NEGOTIATED_DRX_PARAMETERS: {
      pIEI = std::make_shared<NegotiatedDrxParametersIE>();
    break;
    }
    case InformationElementType::IE_NETWORK_DAYLIGHT_SAVING_TIME: {
      pIEI = std::make_shared<NetworkDaylightSavingTimeIE>();
    break;
    }
    case InformationElementType::IE_NON_3GPP_DEREGISTRATION_TIMER_VAL: {
      pIEI = std::make_shared<Non3GPPDeregistrationTimerValueIE>();
    break;
    }
      case InformationElementType::IE_NON_CURRENT_NATIVE_NAS_KEY_SET_IDENTIFIER: {
        pIEI = std::make_shared<NonCurrentNativeNasKeySetIdentifierIE>();
    break;
    }
      case InformationElementType::IE_OLD_PDU_SESSION_ID: {
        pIEI = std::make_shared<OldPduSessionIdIE>();
    break;
    }
    case InformationElementType::IE_REPLAYED_S1_UE_SECURITY_CAPABILITY: {
      pIEI = std::make_shared<ReplayedS1UeSecurityCapabilityIE>();
    break;
    }
      case InformationElementType::IE_REQUESTED_DRX_PARAMETERS: {
        pIEI = std::make_shared<RequestedDrxParametersIE>();
    break;
    }
      case InformationElementType::IE_REQUESTED_NSSAI: {
        pIEI = std::make_shared<RequestedNssaiIE>();
    break;
    }
      case InformationElementType::IE_REQUESTED_QOS_FLOW_DESCRIPTIONS: {
        pIEI = std::make_shared<RequestedQosFlowDescriptionsIE>();
    break;
    }
      case InformationElementType::IE_REQUESTED_QOS_RULES: {
        pIEI = std::make_shared<RequestedQosRulesIE>();
    break;
    }
      case InformationElementType::IE_RQ_TIMER_VALUE: {
        pIEI = std::make_shared<RQTimerValueIE>();
    break;
    }
      case InformationElementType::IE_SELECTED_EPS_NAS_SECURITY_ALGORITHMS: {
        pIEI = std::make_shared<SelectedEpsNasSecurityAlgorithmsIE>();
    break;
    }
      case InformationElementType::IE_SHORT_NAME_OF_NETWORK: {
        pIEI = std::make_shared<ShortNameOfNetworkIE>();
    break;
    }
      case InformationElementType::IE_T3346_VALUE: {
        pIEI = std::make_shared<T3346ValueIE>();
    break;
    }
      case InformationElementType::IE_T3502_VALUE: {
        pIEI = std::make_shared<T3502ValueIE>();
    break;
    }
      case InformationElementType::IE_T3512_VALUE: {
        pIEI = std::make_shared<T3512ValueIE>();
    break;
    }
      case InformationElementType::IE_UINVERSAL_TIME_AND_LOCAL_TIME_ZONE: {
        pIEI = std::make_shared<UniversalTimeAndLocalTimeZoneIE>();
    break;
    }
     default: {
      break;
    }
    }
    return pIEI;
  }
};

//**************************Information Elements *********************/
} // namespace nas
