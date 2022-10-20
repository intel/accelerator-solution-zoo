#！ /bin/bash
export RTE_SDK=`echo $PWD`/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc

native_linuxapp_gcc_path=$RTE_SDK/x86_64-native-linuxapp-gcc
current_pwd=`echo $PWD`
# echo $native_linuxapp_gcc_path
./configure --with-dpdk-lib=$native_linuxapp_gcc_path CFLAGS=-DMAX_CPUS=152 > build.log 2>&1

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
if [ ! -d $dsa_so_dir ];then
    mkdir $dsa_so_dir
    echo "start build dsa_userlib"
    cd $dsa_so_dir && cmake .. && make
    echo "start config dsa_userlib"
    #cd $dsa_so_dir/../config_dsa && ./setup_dsa.sh configs/4e1w-d.conf
    echo "dsa_userlib done"
fi
echo "done"
cp $dsa_so_dir/lib/libvector_data_streaming.so $current_pwd/apps/example/

echo "start clean temp..."
make clean -k > build.log 2>&1
rm -rf build.log
echo "done"
# echo "*****************************************start modify apps/example/makefile***********************************************"

virtqueue_h_makefile=$current_pwd/apps/example/Makefile
n=70
TMP="DSA_FLD = ../../../dsa_userlib"
sed -i "$[ n ]c $TMP" $virtqueue_h_makefile
n=71
TMP="DSA_INC = -I\${DSA_FLD}/include"
sed -i "$[ n ]c $TMP" $virtqueue_h_makefile
n=72
TMP="MTCP_INC2 =-I\${MTCP_FLD}/src/include"
sed -i "$[ n ]c $TMP" $virtqueue_h_makefile
n=73
TMP="FILES=\${DSA_FLD}/build/lib"
sed -i "$[ n ]c $TMP" $virtqueue_h_makefile
n=74
TMP="INC += \${UTIL_INC} \${MTCP_INC} \${MTCP_INC2} \${DSA_INC} -I\${UTIL_FLD}/include"
sed -i "$[ n ]c $TMP" $virtqueue_h_makefile
n=75
TMP="LIBPATH  = -L\${FILES}"
sed -i "$[ n ]c $TMP" $virtqueue_h_makefile
n=76
TMP="LIBVAR  = -ldsa_userlib"
sed -i "$[ n ]c $TMP" $virtqueue_h_makefile
#n=103
#sed -i "${n} s/-o/\$(LIBPATH) \$(LIBVAR) -o/g" $virtqueue_h_makefile


# echo "*****************************************start modify mtcp/src/makefile***********************************************"
mtcp_src_makefile_path=$current_pwd/mtcp/src/Makefile
n=`grep -n "GCC_OPT += -Wall -fPIC -fgnu89-inline"  $mtcp_src_makefile_path | awk -F':' '{print $1}'` 
TMP="GCC_OPT += -Wall -fPIC -fgnu89-inline"
sed -i "$[ n ]c $TMP" $mtcp_src_makefile_path
#TMP="psio_module.c io_module.c dpdk_module.c netmap_module.c onvm_module.c icmp.c virtqueue.c sfifo.c"
#n=121
#sed -i "$[ n ]c $TMP" $mtcp_src_makefile_path
TMP="DSA_FLD=../../../dsa_userlib/include"
n=77
sed "$[n]i $TMP"  -i $mtcp_src_makefile_path
TMP='INC+=-I${DSA_FLD}'
sed "$[n]a $TMP"  -i $mtcp_src_makefile_path
n=78
TMP="DSAPATH  = ../../../dsa_userlib"
sed "$[n]i $TMP"  -i $mtcp_src_makefile_path
n=79
TMP='DSALIB=${DSAPATH}/build/lib/libvector_data_streaming.so'
sed "$[n]i $TMP"  -i $mtcp_src_makefile_path
n=80
TMP='GCC_OPT += -D DSA_ENABLE'
sed "$[ n ]c $TMP"  -i $mtcp_src_makefile_path

n=151
sed -i "${n} s/\$(OBJS)/\$(OBJS) \$(DSALIB)/g" $mtcp_src_makefile_path

echo "prepare done"
