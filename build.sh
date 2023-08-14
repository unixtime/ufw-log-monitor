#!/bin/bash

export DOCKER_BUILDKIT=1

echo -e "Building Docker Image"

docker build --no-cache -t ufw-log-monitor --compress --force-rm --label 1.0 --push .

echo -e "Done"
