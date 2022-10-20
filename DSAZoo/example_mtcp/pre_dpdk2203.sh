#！ /bin/bash


#clone/build/install dpdk2203

DPDK_INSTALL_DIR=$1
DPDK_ID=${DPDK_INSTALL_DIR:-"~/dpdk_2203_install"}
current_pwd=`pwd`

if [ $# -eq 0 ]; then
  echo "Please input a directory to install DPDK v22.03"
  exit 0
fi

echo $DPDK_ID

clone_and_build_dpdk() {
	git clone -b v22.03 http://dpdk.org/git/dpdk


	cd dpdk
	meson --prefix=${DPDK_ID} build
	ninja -C build
	meson install -C build
	ln -s build x86_64-native-linuxapp-gcc
}

if [ -d dpdk ]; then
	echo "there's already a dpdk dir here! check dpdk branch"
	cd dpdk
	Ver=`git branch -v | awk -F: '{print $2}'`
	if [ ! $Ver ]; then
		echo "not a dpdk repo, remove it and re-clone"
		rm -fr dpdk
		
		clone_and_build_dpdk
	else
		echo "$Ver"
	fi
else
	clone_and_build_dpdk
fi


