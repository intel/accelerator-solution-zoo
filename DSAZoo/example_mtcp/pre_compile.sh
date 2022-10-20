#！ /bin/bash
export RTE_SDK=`echo $PWD`/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc

native_linuxapp_gcc_path=$RTE_SDK/x86_64-native-linuxapp-gcc
current_pwd=`echo $PWD`
# echo $native_linuxapp_gcc_path
./configure --with-dpdk-lib=$native_linuxapp_gcc_path CFLAGS=-DMAX_CPUS=152 

logger_h=`echo $PWD`/mtcp/src/include/logger.h
n=12
TMP="};"
sed -i "$[ n ]c $TMP" $logger_h

util_h=`echo $PWD`/util/include/netlib.h
n=41
TMP="};"
sed -i "$[ n ]c $TMP" $util_h

virtqueue_h=`echo $PWD`/mtcp/src/include/virtqueue.h
n=39
TMP="uint64_t vq_ring_mem; /*"
sed -i "$[ n ]c $TMP" $virtqueue_h

rm -rf apps/example/epping

echo "start build dsa library..."
dsa_so_dir=$PWD/../dsa_userlib/build/
echo $dsa_so_dir

DSA_LIB_PATH=`find $dsa_so_dir -name "*.so"`
echo $DSA_LIB_PATH
if [ $DSA_LIB_PATH ];then
    echo "dsa user library already built"
else
    mkdir $dsa_so_dir
    echo "start build dsa_userlib"
    cd $dsa_so_dir && cmake .. && make
    echo "start config dsa_userlib"
    #cd $dsa_so_dir/../config_dsa && ./setup_dsa.sh configs/4e1w-d.conf
    echo "dsa_userlib done"
fi
echo "done"
cp $dsa_so_dir/lib/libvector_data_streaming.so $current_pwd/apps/example/


echo "prepare done"
