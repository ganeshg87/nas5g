# nas5g

## Introduction:
The "nas5g" library is a software component designed to provide comprehensive support for 5G (Fifth Generation) Network Access Stratum (NAS) functionalities. As a crucial part of 5G network infrastructure, the library aims to simplify the implementation of NAS protocols, ensuring seamless communication between user equipment (UE) and the 5G core network.

## Key Features:

### NAS Protocol Implementation:

The library offers a robust implementation of the 5G NAS protocol stack, enabling communication between UEs and the core network.
Modularity and Extensibility:

Designed with a modular architecture, allowing developers to extend or customize functionalities easily.
Supports integration with other 5G-related libraries and protocols.
Security Considerations:

* Implements essential security features, such as encryption and authentication, to ensure the integrity and confidentiality of communication.
Message Encoding and Decoding:

* Facilitates the encoding and decoding of NAS messages, providing a convenient interface for handling communication at the NAS layer.
UE State Management:

* Manages the state of User Equipment within the 5G network, handling transitions between states as per the 3GPP specifications.
Error Handling and Logging:

* Incorporates robust error-handling mechanisms and logging functionalities to assist 

### Build and run unit test cases
```
ganesh@ganesh-Latitude-3400:~/Ganesh/nas5g/test$ g++ testNasMessage.cpp -o nasmsg -I ../.
ganesh@ganesh-Latitude-3400:~/Ganesh/nas5g/test$ ls
main.cpp  nasmsg  testNasBuffer.cpp  testNasInformationElement.cpp  testNasMessage.cpp
ganesh@ganesh-Latitude-3400:~/Ganesh/nas5g/test$ ls
main.cpp  nasmsg  testNasBuffer.cpp  testNasInformationElement.cpp  testNasMessage.cpp
ganesh@ganesh-Latitude-3400:~/Ganesh/nas5g/test$ g++ testNasInformationElement.cpp -o nasmsg -I ../.
ganesh@ganesh-Latitude-3400:~/Ganesh/nas5g/test$ ./nasmsg 
Before Decode : 7e 
After Decode  : 7e 
ExtendedProtocolDiscriminator testcase successfull.
Before Decode : 2e 
After Decode  : 2e
ganesh@ganesh-Latitude-3400:~/Ganesh/nas5g/test$ g++ testNasBuffer.cpp -o nasmsg -I ../.
ganesh@ganesh-Latitude-3400:~/Ganesh/nas5g/test$ ./nasmsg 
decoding successful..
ganesh@ganesh-Latitude-3400:~/Ganesh/nas5g/test$ 

```

