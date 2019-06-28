#!/usr/bin/env bash
((return 0 2>/dev/null) || [[ $ZSH_EVAL_CONTEXT =~ :file$ ]]) || {
  echo "Please load the file instead."
  echo "example: source envsetup.sh"
  exit 1
}

KERNEL_DIR=$(dirname "$(readlink -f "$0")")
BUILD_DIR=$KERNEL_DIR/out

export KBUILD_COMPILER_STRING=$(clang -v |& sed -e '1!d;s/ (http.\+)//g')

export DTC_EXT=dtc # from https://android.googlesource.com/platform/external/dtc/+/refs/heads/pie-release
export DTPY=mkdtboimg.py # from https://android.googlesource.com/platform/system/libufdt/+/refs/heads/pie-release

export OLDPROMPT="$PS1"
export PS1="(dev) $OLDPROMPT"

mke(){
  mkdir -p $BUILD_DIR
  version=$(git rev-list --tags --max-count=1 | xargs git describe --tags)
  echo "-$version" > {$KERNEL_DIR,$BUILD_DIR}/.scmversion

  make -j$(nproc --all) \
    -C $KERNEL_DIR \
    O=$BUILD_DIR \
    ARCH=arm64 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CC=clang CLANG_TRIPLE=aarch64-linux-gnu- $@ |& tee ../mke.log
  
  test -z "$@" && mke_dtimg
}

mke_dtimg(){
  DTOUT=$BUILD_DIR/dtbo.img
  MKDT=$(which $DTPY)

  if [[ -n "$MKDT" ]];then
    echo "Building overlay dt using $MKDT"
    python2 $MKDT \
      create $DTOUT \
      $(find $BUILD_DIR/arch/arm64/boot/dts/ -iname '*-overlay.dtbo' -print)
    echo "Build done: $DTOUT"
  fi
}

cherry-am(){
  co=cherry.patch
  uri=$(echo $1|cut -d\# -f1)
  curl -o $co $uri.patch && git am < $co && rm $co
}

deactivate(){
  export PS1="$OLDPROMPT"
  unset DTC_EXT KBUILD_COMPILER_STRING OLDPROMPT
  unset -f mke mke_dtimg cherry-am deactivate
}
