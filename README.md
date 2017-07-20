# emp-ot [![Build Status](https://travis-ci.org/emp-toolkit/emp-ot.svg?branch=master)](https://travis-ci.org/emp-toolkit/emp-ot)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

## Installation

1. Install prerequisites using instructions [here](https://github.com/emp-toolkit/emp-readme#detailed-installation).
2. Install [emp-tool](https://github.com/emp-toolkit/emp-tool).
2. `git clone https://github.com/emp-toolkit/emp-ot.git`
3. `cd emp-ot && cmake . && sudo make install`  
    1. By default it will build for Release. `-DCMAKE_BUILD_TYPE=[Release|Debug]` option is also available.
    2. No sudo? change [CMAKE_INSTALL_PREFIX](https://cmake.org/cmake/help/v2.8.8/cmake.html#variable%3aCMAKE_INSTALL_PREFIX)

## Test

### Testing on localhost

   `./run ./bin/[binary] 12345`

with `[binary]=shot` to test semi-honest OTs and `[binary]=mot` for malicious OTs
   
### Testing on localhost

1. Change the IP address in the test code (e.g. [here](https://github.com/emp-toolkit/emp-ot/blob/master/test/shot.cpp#L8))

2. run `./bin/[binary] 1 [port]` on one machine and 
  
   run `./bin/[binary] 2 [port]` on the other machine.
  
## Performance
All numbers are based on single thread, measured in terms of OT per second.

### Localhost
Communication through loopback. [c4.2xlarge](http://www.ec2instances.info/?filter=c4.2xlarge) is used.

|                | OT            | COT          | ROT          |
|----------------|---------------|--------------|--------------|
| NPOT           | 7.3 thousand  |              |              |
| SemiHonest OTe | 13.5 million  | 14 million   | 15 million   |
| COOT           | 12.6 thousand |              |              |
| Malicious OTe  | 10.5 million  | 10.8 million | 11.6 million |

### Local Area Network

Communication through 2.32 Gbps network with ping <= 0.2ms. Two [c4.2xlarge](http://www.ec2instances.info/?filter=c4.2xlarge) are used.

|                | OT            | COT          | ROT          |
|----------------|---------------|--------------|--------------|
| NPOT           | 7.3 thousand  |              |              |
| SemiHonest OTe | 6 million  | 8.9 million | 12 million |
| COOT           | 12.5 thousand |              |              |
| Malicious OTe  | 5.4 million  | 7.6 million | 9.7 million |

## Usage


## Question
Please send email to wangxiao@cs.umd.edu
