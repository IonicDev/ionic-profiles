#!/bin/bash

#####
# Copyright 2017-2018 Ionic Security Inc. All Rights Reserved.
# Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
#####

IMAGE_NAME=buildtools/set/cpp
CONTAINER_NAME=set-registration-build

docker build -t $IMAGE_NAME -f Dockerfile.cpp .
docker run -v "$PWD":/project -v "$IONIC_SDK_PATH":/ionic  -w /project --name $CONTAINER_NAME $IMAGE_NAME /bin/bash -c ' \
    source /etc/profile.d/ionic.sh; \
    pushd /boost && ./bootstrap.sh \
            --with-libraries=regex,system,filesystem,program_options,graph  && \
            ./b2 link=static && popd;  \
    cd /project; \
    mkdir -p build-x86_64; \
    pushd build-x86_64; \
    IONIC_SDK_PATH=/ionic cmake .. -Dplatform=Linux -Darchitecture=x86_64 -DBOOST_ROOT=/boost; \
    make all; \
    popd;'
docker rm $CONTAINER_NAME

echo "Built File:"
file build-x86_64/target/ionic-profiles

