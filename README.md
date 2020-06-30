emp-ot [![Build Status](https://travis-ci.org/emp-toolkit/emp-ot.svg?branch=master)](https://travis-ci.org/emp-toolkit/emp-ot)
=====
<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>


Installation
=====

1. Install prerequisites using instructions [here](https://github.com/emp-toolkit/emp-readme#detailed-installation).
2. Install [emp-tool](https://github.com/emp-toolkit/emp-tool).
3. `git clone https://github.com/emp-toolkit/emp-ot.git`
4. Optionally, if lattice-based OT is desired, install dependencies with `emp-ot/install_packages_lattice.sh`
5. `cd emp-ot && cmake . && sudo make install`  
    1. Alternatively, you can also `cd emp-ot && mkdir -p build && cd build && cmake .. && sudo make install` if out-of-source build is preferred.
    2. By default it will build for Release. `-DCMAKE_BUILD_TYPE=[Release|Debug]` option is also available.
	3. To build with lattice OT, add the flag `-DLATTICEOT=true`
    4. No sudo? change [CMAKE_INSTALL_PREFIX](https://cmake.org/cmake/help/v3.18/variable/CMAKE_INSTALL_PREFIX.html)

Test
=====

Testing on localhost
-----

   `./run ./bin/[binary] 12345`

with `[binary]=shot` to test semi-honest OTs and `[binary]=mot` for malicious OTs
   
Testing on localhost
-----

1. Change the IP address in the test code (e.g. [here](https://github.com/emp-toolkit/emp-ot/blob/master/test/shot.cpp#L8))

2. run `./bin/[binary] 1 [port]` on one machine and 
  
   run `./bin/[binary] 2 [port]` on the other machine.
  
Performance
=====
All numbers are based on single thread, measured in terms of OT per second. Using three threads is expected to fill a 10Gbps network.

Localhost
-----
Communication through loopback. [c4.2xlarge](http://www.ec2instances.info/?filter=c4.2xlarge) is used.

|                | OT            | COT          | ROT          |
|----------------|---------------|--------------|--------------|
| NPOT           | 7.3 thousand  |              |              |
| SemiHonest OTe | 13.5 million  | 14 million   | 15 million   |
| COOT           | 12.6 thousand |              |              |
| Malicious OTe  | 10.5 million  | 10.8 million | 11.6 million |

Local Area Network
-----

Communication through 2.32 Gbps network with ping <= 0.2ms. Two [c4.2xlarge](http://www.ec2instances.info/?filter=c4.2xlarge) are used.

|                | OT            | COT          | ROT          |
|----------------|---------------|--------------|--------------|
| NPOT           | 7.3 thousand  |              |              |
| SemiHonest OTe | 6 million  | 8.9 million | 12 million |
| COOT           | 12.5 thousand |              |              |
| Malicious OTe  | 5.4 million  | 7.6 million | 9.7 million |

Usage
=====
All oblivious transfer protocols are implemented with network as a template. Therefore customized network implementation with [sending](https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/io/io_channel.h#L15) and [receiving](https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/io/io_channel.h#L18) can be easily hooked up with `emp-ot`. [`NetIO`](https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/io/net_io_channel.h#L26) is used for all tests and examples in the following.

A Simple Example for String OT
-----

```cpp
#include<emp-tool/emp-tool.h> // for NetIO, etc
#include<emp-ot/emp-ot.h>   // for OTs

block b0[length], b1[length];
bool c[length];
NetIO io(party==ALICE ? nullptr:"127.0.0.1", port); // Create a network with Bob connecting to 127.0.0.1
NPOT<NetIO> np(&io); // create a Naor Pinkas OT using the network above
if (party == ALICE)
// ALICE is sender, with b0[i] and b1[i] as messages to send
    np.send(b0, b1, length); 
else
// Bob is receiver, with c[i] as the choice bit 
// and obtains b0[i] if c[i]==0 and b1[i] if c[i]==1
    np.recv(b0, c, length);  
```
Note that `NPOT` can be replaced to `COOT`, `SHOTExtension` or `MOTExtension` (default rho=40) without changing any other part of the code. In fact, `*OTExtension` calls baseOT internally so you should (almost) never need to call `NPOT` or `COOT` yourself.

Variantions
-----

Correlated OT and Random OT are supported for `*OTExtension`. See following as an example.
```cpp
block delta;

SHOTExtension<NetIO> ote(&io); // create a semi honest OT extension

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
The above code also works for `MOTExtension<NetIO>`. However, cot no longer guarantee that same Delta is used. An additional interface is provided.

```cpp
block deltas[length];
//Correlated OT
if (party == ALICE)
    ote.send_cot(b0, deltas, length);
else
    ote.recv_cot(b0, c, length);
```
Note that you can call `send` or `send_cot` or `send_rot` multiple times without repeating baseOT; however, the role (`send`/`recv`) cannot be reversed for the same object.

More details
-----
- Base OTs are accelerated using ECC, from [relic](https://github.com/relic-toolkit/relic).
- Inspired by Keller et al.[KOS15], F_COTe is split out [separately](emp-ot/ot_extension.h), from which semi-honest and malicious OT extension are built. Future works that optimize OT extension, but still uses IKNP can also be built on top of that. 
- `MOTextension` also supports committing OT, which allows the sender to open *all* messages at a later stage. See [here](emp-ot/mextension.h#L27) for more parameters in the constructor and [here](emp-ot/mextension.h#L286) on how to open.
- As part of `emp-toolkit`, it is being used in `emp-sh2pc`, `emp-m2pc`, and other projects that will be open sourced soon.

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
Lattice-based OT is contributed by David Van Cleve, Matthew Soulanille, and William Wang.

This work was supported in part by the National Science Foundation under Awards #1111599 and #1563722.
