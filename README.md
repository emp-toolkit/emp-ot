emp-ot [![Build Status](https://travis-ci.org/emp-toolkit/emp-ot.svg?branch=master)](https://travis-ci.org/emp-toolkit/emp-ot)
=====
<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

Protocols
=====
This repo contains state-of-the-art OT implementations. Include two base OTs, IKNP OT extension and Ferret OT extension. All hash functions used for OTs are implemented with [MiTCCR](https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/utils/mitccrh.h#L8) for optimal concrete efficiency.

Installation
=====

1. Install Openssl. Instructions are available [here](https://github.com/emp-toolkit/emp-readme#detailed-installation).
2. Install [emp-tool](https://github.com/emp-toolkit/emp-tool).
3. `git clone https://github.com/emp-toolkit/emp-ot.git`
5. `cd emp-ot && cmake . && sudo make install`  
    1. Alternatively, you can also `cd emp-ot && mkdir -p build && cd build && cmake .. && sudo make install` if out-of-source build is preferred.
    2. By default it will build for Release. `-DCMAKE_BUILD_TYPE=[Release|Debug]` option is also available.
	3. To build with lattice OT, add the flag `-DLATTICEOT=true`
    4. No sudo? change [CMAKE_INSTALL_PREFIX](https://cmake.org/cmake/help/v2.8.8/cmake.html#variable%3aCMAKE_INSTALL_PREFIX)

Test
=====

Testing on localhost
-----

   `./run ./bin/[binary]`

with `[binary]=ot` for common OT functionalities, `[binary]=ferret` for ferret specific functionalities. The script `run` will locally open two programs.
   
Testing on two
-----

1. Change the IP address in the test code (e.g. [here](https://github.com/emp-toolkit/emp-ot/blob/master/test/ot.cpp))

2. run `./bin/[binary] 1 [port]` on one machine and 
  
   run `./bin/[binary] 2 [port]` on the other machine.
  
Performance
=====
Hardware: AWS c5.2xlarge

### 50 Mbps
```
128 NPOTs:	Tests passed.	49974 us
Passive IKNP OT	Tests passed.	129178 OTps
Passive IKNP COT	Tests passed.	391626 OTps
Passive IKNP ROT	Tests passed.	389552 OTps
128 COOTs:	Tests passed.	29566 us
Active IKNP OT	Tests passed.	129114 OTps
Active IKNP COT	Tests passed.	390429 OTps
Active IKNP ROT	Tests passed.	388819 OTps
Passive FERRET OT	Tests passed.	190968 OTps
Passive FERRET COT	Tests passed.	1.9824e+07 OTps
Passive FERRET ROT	Tests passed.	1.99563e+07 OTps
Active FERRET OT	Tests passed.	191105 OTps
Active FERRET COT	Tests passed.	1.77388e+07 OTps
Active FERRET ROT	Tests passed.	1.9178e+07 OTps

Active FERRET: 32 ns per RECOT
```

### 10 Gbps
```
128 NPOTs:	Tests passed.	10798 us
Passive IKNP OT	Tests passed.	1.68777e+07 OTps
Passive IKNP COT	Tests passed.	3.29181e+07 OTps
Passive IKNP ROT	Tests passed.	2.34461e+07 OTps
128 COOTs:	Tests passed.	9526 us
Active IKNP OT	Tests passed.	1.52476e+07 OTps
Active IKNP COT	Tests passed.	2.71435e+07 OTps
Active IKNP ROT	Tests passed.	2.03387e+07 OTps
Passive FERRET OT	Tests passed.	1.29035e+07 OTps
Passive FERRET COT	Tests passed.	2.57758e+07 OTps
Passive FERRET ROT	Tests passed.	2.60869e+07 OTps
Active FERRET OT	Tests passed.	1.25404e+07 OTps
Active FERRET COT	Tests passed.	2.47524e+07 OTps
Active FERRET ROT	Tests passed.	2.52575e+07 OTps

Active FERRET: 27 ns per RECOT
```

Usage
=====
Our test files already provides useful sample code. Here we provide an overview.

Standard OT
-----

```cpp
#include<emp-tool/emp-tool.h> // for NetIO, etc
#include<emp-ot/emp-ot.h>   // for OTs

block b0[length], b1[length];
bool c[length];
NetIO io(party==ALICE ? nullptr:"127.0.0.1", port); // Create a network with Bob connecting to 127.0.0.1
OTNP<NetIO> np(&io); // create a Naor Pinkas OT using the network above
if (party == ALICE)
// ALICE is sender, with b0[i] and b1[i] as messages to send
    np.send(b0, b1, length); 
else
// Bob is receiver, with c[i] as the choice bit 
// and obtains b0[i] if c[i]==0 and b1[i] if c[i]==1
    np.recv(b0, c, length);  
```
Note that `NPOT` can be replaced to `OTCO`, `IKNP`, or `FerretCOT` without changing any other part of the code.

Correlated OT and Random OT
-----

Correlated OT and Random OT are supported for `IKNP` and `FerretCOT`. See following as an example.
```cpp
block delta;

IKNP<NetIO> ote(&io, false); // create a semi honest OT extension

//Correlated OT
if (party == ALICE)
    ote.send_cot(b0, delta, length);
else
    ote.recv_cot(b0, c, length);
    
//Random OT
if (party == ALICE)
    ote.send_rot(b0, b1, length);
else
    ote.recv_rot(b0, c, length);
```

Ferret OT
-----

Ferret OT produces correlated OT with random choice bits (rcot). Our implementation provides two interface `ferretot.rcot()` and `ferretot.rcot_inplace()`. While the first one support filling an external array of any length, an extra memcpy is needed. The second option work on the provided array directly and thus avoid the memcpy. However, it produces a fixed number of OTs (`ferretcot->n`) for every invocation. The [sample code](https://github.com/emp-toolkit/emp-ot/blob/master/test/ferret.cpp#L7) is mostly self-explainable on how to use it.

Note that the choice bit is embedded as the least bit of the `block` on the receiver's side. To make sure the correlation works for all bits, the least bit of Delta is 1. This can be viewed as an extension of the point-and-permute technique. See [this code](https://github.com/emp-toolkit/emp-ot/blob/master/emp-ot/ferret/ferret_cot.hpp#L211) on how ferret is used to fullfill standard `cot` interface.

Citation
=====
```latex
@misc{emp-toolkit,
   author = {Xiao Wang and Alex J. Malozemoff and Jonathan Katz},
   title = {{EMP-toolkit: Efficient MultiParty computation toolkit}},
   howpublished = {\url{https://github.com/emp-toolkit}},
   year={2016}
}
```

Question
=====
Please send email to wangxiao@cs.northwestern.edu

## Acknowledgement
This work was supported in part by the National Science Foundation under Awards #1111599 and #1563722.
