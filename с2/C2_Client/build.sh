#!/bin/bash
set -e

BUILD_DIR=build

if [ "$1" == "cmake" ]; then
    rm -rf $BUILD_DIR
    mkdir $BUILD_DIR
    cd $BUILD_DIR
    cmake ..
    make
    cd ..
elif [ "$1" == "make" ]; then
    make clean
    make
else
    echo "Usage: $0 {cmake|make}"
    exit 1
fi
