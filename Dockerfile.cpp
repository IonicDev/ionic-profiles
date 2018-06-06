FROM centos:7

RUN yum -y update  && \
    yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    yum -y update  && \
    yum -y upgrade && \
    yum install -y xmlsec1-openssl python-pip libcurl-devel && \
    yum groupinstall -y "Development Tools" && \
    pip install requests

RUN curl -O https://cmake.org/files/v3.7/cmake-3.7.1-Linux-x86_64.sh
RUN echo y | sh cmake-3.7.1-Linux-x86_64.sh
ENV PATH /cmake-3.7.1-Linux-x86_64/bin:$PATH

RUN yum install -y wget
RUN wget https://dl.bintray.com/boostorg/release/1.66.0/source/boost_1_66_0.tar.bz2 && tar xvjf boost_1_66_0.tar.bz2
RUN mv boost_1_66_0 /boost

RUN mkdir /project
RUN mkdir /ionic
WORKDIR /project
