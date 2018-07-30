FROM centos:7.5.1804

RUN yum -y update
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
RUN yum -y update
RUN yum -y upgrade
RUN yum install -y xmlsec1-openssl python-pip libcurl-devel
RUN yum groupinstall -y "Development Tools"
RUN pip install requests

RUN curl -O https://cmake.org/files/v3.7/cmake-3.7.1-Linux-x86_64.sh
RUN echo y | sh cmake-3.7.1-Linux-x86_64.sh
ENV PATH /cmake-3.7.1-Linux-x86_64/bin:$PATH

RUN yum install -y wget
RUN wget https://dl.bintray.com/boostorg/release/1.66.0/source/boost_1_66_0.tar.bz2 && tar xvjf boost_1_66_0.tar.bz2
RUN mv boost_1_66_0 /boost

RUN mkdir /project
RUN mkdir /ionic
WORKDIR /project

ARG USER_ID=1010
ARG GROUP_ID=1010
RUN groupadd -g $GROUP_ID user && \
    useradd -u $USER_ID -s /bin/sh -g user user