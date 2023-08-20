#!/bin/bash

RELEASE_VERSION="1.0"
DOCKER_REPO="unixtime"        # default repository name
PUBLISH="True"               # default publish option

export DOCKER_BUILDKIT=1

echo -e "Building Docker Image"

# Check if PUBLISH is set to True
if [ "$PUBLISH" == "True" ]; then
    ### Build Docker Image with no cache and push to Docker Hub
    docker build --no-cache -t $DOCKER_REPO/ufw-log-monitor --compress --force-rm --label $RELEASE_VERSION --push .
else
    ### Build Docker Image with no cache locally
    docker build --no-cache -t ufw-log-monitor --compress --force-rm --label $RELEASE_VERSION .
fi

echo -e "Done"
