#!/bin/bash
set -e
apt-get update
apt-get install -y clang libelf-dev libz-dev libpcap-dev make m4 autoconf autopoint flex bison pkg-config gawk
