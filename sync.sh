#!/bin/bash
TARGET_DIR="/root/cybervpn"
GIT_REPO="https://github.com/xyzval/VVIP.git"
BRANCH="main"

if [ ! -d "$TARGET_DIR" ]; then
    git clone -b $BRANCH $GIT_REPO $TARGET_DIR
else
    cd $TARGET_DIR
    git pull origin $BRANCH
fi
