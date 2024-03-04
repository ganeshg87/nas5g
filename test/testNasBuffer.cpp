
#include "NasBuffer.h"
#include <iostream>
#include <string>

using namespace std;
using namespace nas;

bool validateInitialUeMsgHexBuf() {
  std::string initialUeMsgHex =
      "7e124179000d0109f1070000000000000000102e04f0f0f0f0";
  NasBuffer buffer(initialUeMsgHex);
  if (buffer.DecodeU8() != 0x7e) {
    return false;
  }
  if (buffer.DecodeNibble() != 0x1) {
    return false;
  }
  if (buffer.DecodeNibble() != 0x2) {
    return false;
  }
  if (buffer.DecodeU8() != 0x41) {
    return false;
  }
  if (buffer.DecodeNibble() != 0x7) {
    return false;
  }
  if (buffer.DecodeNibble() != 0x9) {
    return false;
  }
  return true;
}
int main() {
  if (validateInitialUeMsgHexBuf()) {
    std::cout << "decoding successful.." << std::endl;
  }
  return 0;
}