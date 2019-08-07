FROM centos:7.5.1804

RUN yum -y update \
    && yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
    && yum -y update && yum -y upgrade && yum install -y xmlsec1-openssl python-pip libcurl-devel which \
    && yum groupinstall -y "Development Tools" \
    && yum install -y wget \
    && pip install requests \
    && curl -O https://cmake.org/files/v3.7/cmake-3.7.1-Linux-x86_64.sh \
    && echo y | sh cmake-3.7.1-Linux-x86_64.sh \
    && mkdir /project && mkdir /ionic

ENV PATH /cmake-3.7.1-Linux-x86_64/bin:$PATH

WORKDIR /project
