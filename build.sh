#!/bin/bash

LOCALVERSION=" $1"
export LOCALVERSION

DTPY=""
DTC_EXT=""
LLVM_GOLD_PLUGIN=""
KERNEL_DIR=""
NEWPATH=""

HOST=$(uname)
NPROC=4

if [ "$HOST" == "Darwin" ]
then
	DEV_DIR="/Volumes/mi9se"
	KERNEL_DIR="$DEV_DIR/kowalski-grus"

	rm -f $(find $KERNEL_DIR/out/techpack -name '*.o' -type f)

	FINDUTILS_BIN="/usr/local/opt/findutils/libexec/gnubin"
	COREUTILS_BIN="/usr/local/opt/coreutils/libexec/gnubin"
	DTC_EXT="/usr/local/bin/dtc"
	DTPY="/usr/local/bin/mkdtboimg.py"

	GCC_BIN="$DEV_DIR/toolchains/gcc/bin"
	LLVM_DIR="$DEV_DIR/toolchains/clang"
	LLVM_GOLD_PLUGIN="$LLVM_DIR/lib64/LLVMgold.dylib"

	NEWPATH=/usr/local/bin:$FINDUTILS_BIN:$COREUTILS_BIN:$GCC_BIN:$LLVM_DIR/bin:$PATH
elif [ "$HOST" == "Linux" ]
then
	DEV_DIR="/media/ivan/external/mi9se"
	KERNEL_DIR="$DEV_DIR/kowalski-grus"

	DTC_EXT="$DEV_DIR/helpers/dtc/dtc"
	DTPY="$DEV_DIR/helpers/mkdtboimg.py"
	
	GCC_BIN="$DEV_DIR/toolchains/gcc/bin"
	LLVM_DIR="$DEV_DIR/toolchains/clang"
	LLVM_GOLD_PLUGIN="$LLVM_DIR/lib64/LLVMgold.so"

	NPROC=$(nproc)

	NEWPATH=$GCC_BIN:$LLVM_DIR/bin:$PATH
fi

BUILD_DIR=$KERNEL_DIR/out

export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-androidkernel-

export DTC_EXT LLVM_GOLD_PLUGIN
export PATH=$NEWPATH

mke_dtimg(){
  DTOUT=$BUILD_DIR/arch/arm64/boot/dtbo.img

  if [[ -n "DTPY" ]];then
    echo "Building overlay dt using $DTPY"
    python2.7 $DTPY \
      create $DTOUT \
      $(find $BUILD_DIR/arch/arm64/boot/dts/ -iname '*-overlay.dtbo' -print)
    echo "Build done: $DTOUT"
  fi
}

mkdir -p $BUILD_DIR
make O=$BUILD_DIR kowalski_defconfig
make -j$NPROC O=$BUILD_DIR CC=clang CLANG_TRIPLE=aarch64-linux-gnu-

if [ $? -eq 0 ]
then 
	mke_dtimg
fi


