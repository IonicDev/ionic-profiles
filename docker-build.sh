#!/bin/bash

#####
# Copyright 2017-2018 Ionic Security Inc. All Rights Reserved.
# Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
#####

#export IONIC_SDK_PATH="${WORKSPACE}/ionic"
export ARTIFACTORY_USER=${artifactory_user}
export ARTIFACTORY_PASS=${artifactory_passwd}
#export PATH=$PATH:/cmake-3.7.1-Linux-x86_64/bin

echo "export ARTIFACTORY_USER=$ARTIFACTORY_USER" > artifactory.sh
echo "export ARTIFACTORY_PASS=$ARTIFACTORY_PASS" >> artifactory.sh

IMAGE_NAME=buildtools/set/cpp
CONTAINER_NAME=set-registration-build

cd set-register
docker build -t $IMAGE_NAME -f Dockerfile.cpp .
docker run -v "$PWD"/..:/project -v "$IONIC_SDK_PATH":/ionic -w /project --name $CONTAINER_NAME $IMAGE_NAME /bin/bash -c ' \
    export IONIC_SDK_PATH="/ionic" \
    source /etc/profile.d/ionic.sh; \
    source artifactory.sh; \
    cd set-register; \
    python ../build_jenkins_register.py libs; \
    mkdir -p build-x86_64; \
    pushd build-x86_64; \
    cmake .. -Dplatform=Linux -Darchitecture=x86_64 -DBOOST_ROOT=/project/boost; \
    make all; \
    popd; \
    '
docker rm $CONTAINER_NAME

echo "Built File:"
ls -la build-x86_64/target
file build-x86_64/target/ionic-profiles
