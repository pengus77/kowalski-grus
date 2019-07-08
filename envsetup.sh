#!/bin/bash

((return 0 2>/dev/null) || [[ $ZSH_EVAL_CONTEXT =~ :file$ ]]) || {
  echo "Please load the file instead."
  echo "example: source envsetup.sh"
  exit 1
}

KERNEL_DIR="/Volumes/mi9se/kowalski-grus"
BUILD_DIR=$KERNEL_DIR/out

export PATH=/usr/local/opt/coreutils/libexec/gnubin:/Volumes/mi9se/toolchains/gcc/bin:$PATH
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-android-
export DTC_EXT=/usr/local/bin/dtc
export DTPY=/usr/local/bin/mkdtboimg.py

mke(){
  mkdir -p $BUILD_DIR
  make O=$BUILD_DIR grus_user_defconfig
  make -j4 O=$BUILD_DIR CC=/Volumes/mi9se/toolchains/clang/bin/clang CLANG_TRIPLE=aarch64-linux-gnu-

  if [ $? -eq 0 ]
  then 
    mke_dtimg
  fi
}

mke_dtimg(){
  DTOUT=$BUILD_DIR/arch/arm64/boot/dtbo.img

  if [[ -n "$MKDT" ]];then
    echo "Building overlay dt using $MKDT"
    python2.7 $DTPY \
      create $DTOUT \
      $(find $BUILD_DIR/arch/arm64/boot/dts/ -iname '*-overlay.dtbo' -print)
    echo "Build done: $DTOUT"
  fi
}

