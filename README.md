# ionic-profiles Tool 

```
#####
# Copyright 2017-2019 Ionic Security Inc. All Rights Reserved.
# Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
#####
```

This tool is intended to provide Ionic profile management, including creation, deletion, selection, etc. It builds upon ServerEnrollmentTool which originally existed to enable Ionic's Generated SAML Assertion method of enrollment authentication, and this version also supports email enrollment.

See the documentation for usage information and pre-requisite steps.

### Build Requirements
- Cmake 3.1
- libcurl-dev installed
- g++ 4.8.4+
- IONIC_SDK_PATH environment variable must be set to the absolute path of a directory where the SDK libs will be placed

### Build

#### Inside Docker
1. Download and unpack the Ionic C++ SDK for Linux.
2. Ensure you have the environment variable `$IONIC_SDK_PATH` set on your host system to where the unpacked Linux SDK is located, e.g. the path
 `$IONIC_SDK_PATH/ISAgentSDKCpp/Lib/Linux` should exist for example.
3. Run `./docker-build.sh` for it to be built for a Linux x64 CentOS7 target within Docker and output written to `build-x86_64/`.

Note that you can modify the `Dockerfile.cpp` and `docker-build.sh` scripts to build on other platforms as desired.

#### Locally
In a properly configured Linux environment, including the environment variable `$IONIC_SDK_PATH` set, then run the following.

For x64 systems on Linux with boost libraries 1.54.0 or greater use:
```bash
mkdir -p build-x86_64
cd build-x86_64 && cmake .. -Dplatform=Linux -Darchitecture=x86_64
make all
```

See the Boost section below if the build fails to find the necessary Boost libraries.

For x86 systems on Linux with boost libraries 1.54.0 or greater use:
```bash
mkdir -p build-x86
cd build-x86 && export CXXFLAGS="-m32 -std=c++0x" && cmake .. -Dplatform=Linux -Darchitecture=i386
make all
```

See the Boost section below if the build fails to find the necessary Boost libraries.

#### Boost
If the build can not find the correct boost libraries on your system then:
- Download the distribution [Boost 1.66](https://dl.bintray.com/boostorg/release/1.66.0/source/) and unpack it.  
- Set the environment variable `BOOST_ROOT` to the path of the directory that contains the unpacked distribution.
- Build the required boost libraries in the distribution
```bash
pushd $BOOST_ROOT && ./bootstrap.sh \
            --with-libraries=regex,system,filesystem,program_options,graph  && \
            ./b2 link=static && popd
```

### Run Requirements
haveged - Needed to prevent extensive delay when running IonicTools on headless Linux systems.

### Preparation
1. Install haveged

```bash
sudo yum -y install haveged
```

2. Start entropy daemon

```bash
sudo haveged -w 1024
```



