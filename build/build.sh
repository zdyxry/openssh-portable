#!/usr/bin/bash

VERSION="9.3"

docker build -t openssh-$VERSION -f build/Dockerfile .
cid=$(docker create openssh-$VERSION)
docker cp $cid:/root/rpmbuild/RPMS/ .
docker rm -v $cid
