#!/bin/bash

#####
# Copyright 2017-2019 Ionic Security Inc. All Rights Reserved.
# Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
#####

IMAGE_NAME=buildtools/set/cpp
CONTAINER_NAME=set-registration-build

if [[ ! -d $IONIC_SDK_PATH/ISAgentSDKCpp ]] ; then
  echo "ERROR: Ionic SDK (ISAgentSDKCpp) not found in IONIC_SDK_PATH: $IONIC_SDK_PATH"
  echo "Please download and install Ionic SDK for Linux from the Downloads page at https://dev.ionic.com"
  exit
fi

if [[ -z "${IONIC_BUILD_APP_VERSION}" ]]; then
  VERSION_ENV=""
else
  VERSION_ENV="-e IONIC_BUILD_APP_VERSION=$IONIC_BUILD_APP_VERSION"
fi

if [[  -d "../boost" ]]; then
  BOOSTPATH="-v $PWD/../boost:/project/boost"
else
  BOOSTPATH=""
fi

echo "Boost path:   $BOOSTPATH"


[[ "$(docker ps -a -f name=$CONTAINER_NAME | tail -n +2 2> /dev/null)" != "" ]] && docker rm $CONTAINER_NAME
docker build -t $IMAGE_NAME -f Dockerfile.cpp .
docker run -v "$PWD":/project -v "$IONIC_SDK_PATH":/ionic $BOOSTPATH \
    --user $(id -u):$(id -g) \
    -w /project \
    $VERSION_ENV \
    --name $CONTAINER_NAME $IMAGE_NAME \
    /bin/bash -c ' \
    export IONIC_SDK_PATH="/ionic"; \
    if [[ ! -d boost ]] ; then \
        if [[ ! -f boost_1_66_0.tar.bz2 ]] ; then \
            echo "Downloading Boost tar file" ; \
            wget -q  https://dl.bintray.com/boostorg/release/1.66.0/source/boost_1_66_0.tar.bz2 ; \
        fi ; \
        echo "Extracting Boost from tar file" ; \
        tar xjf boost_1_66_0.tar.bz2 ; \
        echo "Moving Boost to /project/boost" ; \
        mv boost_1_66_0 /project/boost ; \
    fi ; \
    cd /project/boost; \
    echo "Building Boost libraries" ; \
    ./bootstrap.sh --with-libraries=system,filesystem,program_options; \
    ./b2 link=static; \
    cd /project; \
    mkdir -p build-x86_64; \
    pushd build-x86_64; \
    cmake .. -Dplatform=Linux -Darchitecture=x86_64 -DBOOST_ROOT=/project/boost; \
    echo "==== Build x86_64 ====" ; \
    make all; \
    popd; \
    echo "Build Complete" ; \
    '

# remove docker container as part of cleanup
docker rm $CONTAINER_NAME

echo "Built File:"
ls -la build-x86_64/target
file build-x86_64/target/ionic-profiles
