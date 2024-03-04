#pragma once

#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "NasEnum.h"
#include "NasUtils.h"
namespace nas {

class OctetBuffer {
private:
  std::vector<uint8_t> m_buffer;
  mutable uint32_t m_currentIndex = 0;
  mutable bool m_isLowerNibble = false;

  /*
    <------Big Endian Byte-------->
    MSBit.8..7..6..5..4..3..2..1...LSBit
    UpplerNibble     LowerNibble
  */

  uint8_t DecodeU8UpperNibble() const {
    return (m_buffer[m_currentIndex] >> 4) & 0x0F;
  }
  void EncodeU8UpperNibble(uint8_t v) {
    m_buffer.emplace_back((v & 0x0F) << 4);
  }

  uint8_t DecodeU8LowerNibble() const {
    return (m_buffer[m_currentIndex++]) & 0x0F;
  }

  void EncodeU8LowerNibble(uint8_t v) {
    if (m_buffer.empty()) {
      m_buffer.emplace_back(v);
    } else {
      uint8_t &b = m_buffer.back();
      b = ((b & 0xF0) | ((v & 0x0F)));
    }
  }

protected:
  uint8_t GetOctet(size_t index) const {
    if (index < m_buffer.size())
      return m_buffer[index];
    return 0;
  }

public:
  bool IsBufferExceeds(uint8_t bufferNeeded) const {
    return (m_currentIndex + bufferNeeded) > (m_buffer.size() - 1);
  }
  /*
   * TODO
          if constexpr (std::endian::native == std::endian::big)
          {
              // Big endian system
          }
          else
          {
              //constexpr (std::endian::native == std::endian::little)
              // Little endian system

          }
  */

  OctetBuffer() {}
  OctetBuffer(uint8_t *pBuffer, size_t size) {
    if (pBuffer && size) {
      for (uint32_t i = 0; i < size; ++i) {
        m_buffer.emplace_back(pBuffer[i]);
      }
    }
  }
  OctetBuffer(const std::vector<uint8_t> &nasHexBuffer) {
    m_buffer = nasHexBuffer;
  }

  OctetBuffer(const std::string &nasBuffer) {
    m_buffer = NasUtils::HexStringToVector(nasBuffer);
  }


  bool isEqual(const OctetBuffer &octetBuffer) {
    if (m_buffer == octetBuffer.m_buffer)
      return true;
    return false;
  }

  size_t Size() const { return m_buffer.size(); }
  uint8_t GetCurrentOctet() const { return GetOctet(m_currentIndex); }

  bool EndOfBuffer() const { return m_currentIndex > (m_buffer.size() - 1); }

  void EncodeU8(const uint8_t &v) { m_buffer.emplace_back(v); }

  uint8_t DecodeU8() const { return m_buffer[m_currentIndex++]; }

  void EncodeU16(const uint16_t &v) {
    EncodeU8(static_cast<uint8_t>(v >> 8));
    EncodeU8(static_cast<uint8_t>(v));
  }
  uint16_t DecodeU16() const {
    uint16_t v = 0x0;

    v = ((static_cast<uint16_t>(m_buffer[m_currentIndex++])) << 8);
    v = v | (static_cast<uint16_t>(m_buffer[m_currentIndex++]));

    return v;
  }

  void EncodeU32(const uint32_t &v) {
    EncodeU8(static_cast<uint8_t>(v >> 24));
    EncodeU8(static_cast<uint8_t>(v >> 16));
    EncodeU8(static_cast<uint8_t>(v >> 8));
    EncodeU8(static_cast<uint8_t>(v));
  }
  uint32_t DecodeU32() const {
    uint32_t v = 0x0;
    v = ((static_cast<uint32_t>(m_buffer[m_currentIndex++])) << 24);
    v = v | ((static_cast<uint32_t>(m_buffer[m_currentIndex++])) << 16);
    v = v | ((static_cast<uint32_t>(m_buffer[m_currentIndex++])) << 8);
    v = v | static_cast<uint32_t>(m_buffer[m_currentIndex++]);

    return v;
  }

  void EncodeU64(const uint64_t &v) {
    EncodeU8(static_cast<uint8_t>(v >> 56U));
    EncodeU8(static_cast<uint8_t>(v >> 48U));
    EncodeU8(static_cast<uint8_t>(v >> 40U));
    EncodeU8(static_cast<uint8_t>(v >> 32U));
    EncodeU8(static_cast<uint8_t>(v >> 24U));
    EncodeU8(static_cast<uint8_t>(v >> 16U));
    EncodeU8(static_cast<uint8_t>(v >> 8U));
    EncodeU8(static_cast<uint8_t>(v));
  }
  uint64_t DecodeU64() const {
    uint64_t v = 0x0;
    v = (static_cast<uint64_t>(m_buffer[m_currentIndex++]) << 56U);
    v = v | (static_cast<uint64_t>(m_buffer[m_currentIndex++]) << 48U);
    v = v | (static_cast<uint64_t>(m_buffer[m_currentIndex++]) << 40U);
    v = v | (static_cast<uint64_t>(m_buffer[m_currentIndex++]) << 32U);
    v = v | (static_cast<uint64_t>(m_buffer[m_currentIndex++]) << 24U);
    v = v | (static_cast<uint64_t>(m_buffer[m_currentIndex++]) << 16U);
    v = v | (static_cast<uint64_t>(m_buffer[m_currentIndex++]) << 8U);
    v = v | static_cast<uint64_t>(m_buffer[m_currentIndex++]);

    return v;
  }

  void EncodeUtf8(const std::string &v) {
    m_buffer.insert(m_buffer.end(), v.begin(), v.end());
  }

  void DecodeUtf8(std::string &v, size_t l) const {
    auto begin = m_buffer.begin() + m_currentIndex;
    if (l > (Size() - m_currentIndex)) {
      return;
    }
    auto end = begin + l;
    v.assign(begin, end);

    m_currentIndex += l;
    return;
  }

  void DecodeU8Vector(std::vector<uint8_t> &v, size_t l) const {
    auto begin = m_buffer.begin() + m_currentIndex;

    if (l > (Size() - m_currentIndex)) {
      return;
    }

    auto end = begin + l;
    v.assign(begin, end);

    m_currentIndex += l;
    return;
  }

  void EncodeU8Vector(const std::vector<uint8_t> &v) {
    m_buffer.insert(m_buffer.end(), v.begin(), v.end());
  }

  uint8_t DecodeNibble() const {
    if (m_isLowerNibble) {
      m_isLowerNibble = false;
      return DecodeU8LowerNibble();
    } else {
      m_isLowerNibble = true;
      return DecodeU8UpperNibble();
    }
  }

  void EncodeNibble(uint8_t v) {
    if (m_isLowerNibble) {
      m_isLowerNibble = false;
      EncodeU8LowerNibble(v);
    } else {
      m_isLowerNibble = true;
      EncodeU8UpperNibble(v);
    }
  }

  std::string ToHexString() {
    std::stringstream ss;

    if (m_buffer.size() <= 0)
      return ss.str();

    ss << std::hex << std::setfill('0');
    uint32_t i = 0;
    for (auto &ch : m_buffer) {
      ss << std::hex << std::setw(2) << static_cast<int>(ch) << " ";
      if ((i + 1) % 8 == 0)
        ss << " ";
      if ((i + 1) % 16 == 0)
        ss << "\n";
      ++i;
    }
    return ss.str();
  }

  void clear() {
    m_buffer.clear();
    m_currentIndex = 0;
    m_isLowerNibble = false;
  }
};

/*
The different formats (V, LV, T, TV, TLV, LV-E, TLV-E) and
the five categories of information elements (type 1, 2, 3, 4 and 6)

Totally four categories of standard information elements are defined:
- information elements of format V or TV with value part consisting of 1/2 octet
(type 1);
- information elements of format T with value part consisting of 0 octets (type
2);
- information elements of format V or TV with value part that has fixed length
of at least one octet (type 3);
- information elements of format LV or TLV with value part consisting of zero,
one or more octets (type 4)
- information elements of format LV-E or TLV-E with value part consisting of
zero, one or more octets and a maximum of 65535 octets (type 6). This category
is used in EPS only
*/

class NasBuffer : public OctetBuffer {
public:
  NasBuffer() {}
  NasBuffer(const std::vector<uint8_t> &nasHexBuffer)
      : OctetBuffer(nasHexBuffer) {}
  NasBuffer(const std::string &nasHexBuffer) : OctetBuffer(nasHexBuffer) {}

  ExtendedProtocolDiscriminator GetExtendedProtocolDiscriminator() const {
    ExtendedProtocolDiscriminator epd =
        static_cast<ExtendedProtocolDiscriminator>(GetOctet(0));
    return epd;
  }

  SecurityHeaderType GetSecurityHeaderType() const {
    SecurityHeaderType sht =
        static_cast<SecurityHeaderType>(GetOctet(1) & 0x0F);
    return sht;
  }

  MessageType GetMessageType() const {
    MessageType msgType = MessageType::NOT_DEFINED;
    ExtendedProtocolDiscriminator epd = GetExtendedProtocolDiscriminator();
    uint8_t index = 0;
    switch (epd) {
    case ExtendedProtocolDiscriminator::MOBILITY_MANAGEMENT_MESSAGES: {
      if (SecurityHeaderType::NOT_PROTECTED == GetSecurityHeaderType()) {
        index = 2;
      } else {
        index = 9;
      }
      break;
    }
    case ExtendedProtocolDiscriminator::SESSION_MANAGEMENT_MESSAGES: {
      index = 3;
    }
    default:
      break;
    }
    if (index != 0) {
      msgType = static_cast<MessageType>(GetOctet(index));
    }
    //std::cout << "message type: " << NasUtils::Enum2String(msgType) << std::endl;
    return msgType;
  }

  NasCause DecodeU8Vector(std::vector<uint8_t> &v, size_t l) const {
    OctetBuffer::DecodeU8Vector(v, l);
    if (v.empty()) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }

  NasCause DecodeUtf8(std::string &v, size_t l) const {
    OctetBuffer::DecodeUtf8(v, l);
    if (v.empty()) {
      return NasCause::NAS_CAUSE_FAILURE;
    }
    return NasCause::NAS_CAUSE_SUCCESS;
  }
};

} // namespace nas