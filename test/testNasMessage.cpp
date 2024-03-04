#include <string>
#include "NasBuffer.h"
#include "NasInformationElement.h"
#include "NasMessage.h"
#include "NasUtils.h"

using namespace nas;

bool validateNasMessage(std::string testcase, const std::string &hexBuf) {
  NasBuffer nasBuffer1(hexBuf);
  // std::cout << "Before Decode : \n" << nasBuffer1.ToHexString() << std::endl;
  NasMessage nasMsg;
  if (NasCause::NAS_CAUSE_SUCCESS != nasMsg.Decode(nasBuffer1)) {
    std::cout << testcase << " testcase failed.!" << std::endl;
    return false;
  }

  NasBuffer nasBuffer2;
  if (NasCause::NAS_CAUSE_SUCCESS != nasMsg.Encode(nasBuffer2)) {
    std::cout << testcase << " testcase failed.!" << std::endl;
    return false;
  }
  // std::cout << "After Decode  : \n" << nasBuffer2.ToHexString() << std::endl;
  if (nasBuffer1.isEqual(nasBuffer2)) {
    std::cout << testcase << " testcase successfull." << std::endl;
    return true;
  }
  std::cout << testcase << " testcase failed.!" << std::endl;
  return false;
}

class NasMessageTest {
  std::vector<std::pair<std::string, std::string>> m_testNasMessage;
public:
  void setup() {
    m_testNasMessage = {
        { "RegistrationRequest", "7e004179000d0109f1070000000000000000102e04f0f0f0f0" },
        { "AuthenticationRequest", "7e00560002000021948a586db853c146b5727fa040b2abae201032f89b274d6380004952f420a8a1c3bf" },
        { "AuthenticationResponse", "7e00572d10a43063cf4b041ead3e0b80fd3223d6f4" },
        { "SecurityModeCommand", "7e03896bbca4007e005d020004f0f0f0f0e1" },
        { "SecurityModeComplete", "7e042b67d632007e005e7700094573806121856151f17100237e004179000d0109f1070000000000000000101001002e04f0f0f0f02f020101530100" },
        { "RegistrationAccept", "7e0042010177000bf209f10701004021d2254f54070009f107000001150201015e0106" },
        { "RegistrationComplete", "7e0043" },
        { "ULNasTransport", "7e028176df2a027e00670100152e0101c1ffff91a12801007b000780000a00000d00120181220101250908696e7465726e6574" },
        { "DLNasTransport", "7e02a122f955027e00680100372e0101c211000901000631310101ff0906010004010003290501c0a8800c2201017b000880000d0408080808250908696e7465726e65741201" },
        { "PDUSessionEstablishment", "2e0101c1ffff91a12801007b000780000a00000d00" },
        { "PDUSessionAccept", "2e0101c211000901000631310101ff0906010004010003290501c0a8800c2201017b000880000d0408080808250908696e7465726e6574" },
        { "PDUSessionReleaseRequest", "2e02f6d15924" },
        { "PDUSessionReleaseCommand", "2e02f6d324" },
        { "PDUSessionModificationCommand", "2e0100cb2a060601f40601f47a001a05000691300101fe0501000e2130091002010102ffffffff010175002960000cf20406fefefafa02020101057000175201050187878787030d2130fe091002010102ffffffff7900260560420701600101050120460701700101010203011388030301138804030113880503011388" },
        { "PDUSessionModificationComplete", "2e0100cc" },
        { "DeregistrationRequestUEOriginating", "7e004529000bf264f00001004151100001" },
        { "DeregistrationAcceptUEOriginating", "7e0046" },

    }; 
  }
  bool execute() {
    bool status  = true;
    for(auto& it: m_testNasMessage) {
        status &= validateNasMessage(it.first, it.second);
    }
    return status;
  }

  static bool TestAllNasMessages() {
      NasMessageTest test;
      test.setup(); 
      return test.execute();
  }
};

int main() {

  if (!NasMessageTest::TestAllNasMessages()) {
    std::cout << "Failed Nas Message Test..?\n";
  } else {
    std::cout << "All test cases Passed..!!!!\n";
  }
  return 0;
}