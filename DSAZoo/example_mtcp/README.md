[![Build Status](https://travis-ci.org/eunyoung14/mtcp.svg?branch=master)](https://travis-ci.org/eunyoung14/mtcp)
[![Build Status](https://scan.coverity.com/projects/11896/badge.svg)](https://scan.coverity.com/projects/eunyoung14-mtcp)

# README

mTCP is a highly scalable user-level TCP stack for multicore systems. 
mTCP source code is distributed under the Modified BSD License. For 
more detail, please refer to the LICENSE. The license term of io_engine 
driver and ported applications may differ from the mTCP’s.

## Prerequisites

We require the following libraries to run mTCP.
- `libdpdk` (Intel's DPDK package*) or `libps` (PacketShader I/O engine library) or `netmap` driver 
- `libnuma`
- `libpthread`
- `librt`
- `libgmp` (for DPDK/ONVM driver)

Compling PSIO/DPDK/NETMAP/ONVM driver requires kernel headers.
- For Debian/Ubuntu, try ``apt-get install linux-headers-$(uname -r)``

We have modified the dpdk package to export net_device stat data 
(for Intel-based Ethernet adapters only) to the OS. To achieve this, we have
created a new LKM dpdk-iface-kmow. We also modified 
``mk/rte.app.mk`` file to ease the compilation
process of mTCP applications. We recommend using our package for DPDK
installation.

### CCP support

You can optionally use [CCP](https://ccp-project.github.io/)'s congestion 
control implementation rather than mTCP's. You'll have wider selection of 
congestion control algorithms with CCP.
(Currently this feature is experimental and under revision.)

Using [CCP](https://ccp-project.github.io/) for congestion control (disabled by
default), requires the CCP library. If you would like to enable CCP, simply run
configure script with `--enable-ccp` option.

1. Install Rust. Any installation method should be fine. We recommend using
   rustup:

    ```bash
    curl https://sh.rustup.rs -sSf | sh -- -y -v --default-toolchain nightly
    ````

2. Install the CCP command line utility:

    ```bash
    cargo install portus --bin ccp
    ```

3. Build the library (comes with Reno and Cubic by default, use `ccp get` to add others):

    ```
    ccp makelib
    ```

4. You will also need to link your application against `-lccp` and `-lstartccp` as demonstrated in apps/example/Makefie.in

## Included directories

mtcp: mtcp source code directory
- mtcp/src: source code
- mtcp/src/include: mTCP’s internal header files
- mtcp/lib: library file
- mtcp/include: header files that applications will use

io_engine: event-driven packet I/O engine (io_engine)
- io_engine/driver - driver source code
- io_engine/lib - io_engine library
- io_engine/include - io_engine header files
- io_engine/samples - sample io_engine applications (not mTCP’s)

dpdk - Intel's Data Plane Development Kit
- dpdk/...

apps: mTCP applications
- apps/example - example applications (see README)
- apps/lighttpd-1.4.32 - mTCP-ported lighttpd (see INSTALL)
- apps/apache_benchmark - mTCP-ported apache benchmark (ab) (see README-mtcp)

util: useful source code for applications

config: sample mTCP configuration files (may not be necessary)


## Install guides

mTCP can be prepared in four ways.

### ***DPDK VERSION***

1. Download DPDK submodule.

    ```bash
    git submodule init
    git submodule update
    ```

2. Setup DPDK.

    ```bash
	./setup_mtcp_dpdk_env.sh [<path to $RTE_SDK>]
    ```

    - Press [15] to compile x86_64-native-linuxapp-gcc version
    - Press [18] to install igb_uio driver for Intel NICs
    - Press [22] to setup 2048 2MB hugepages
    - Press [24] to register the Ethernet ports
    - Press [35] to quit the tool

    - Only those devices will work with DPDK drivers that are listed
      on this page: http://dpdk.org/doc/nics. Please make sure that your
      NIC is compatible before moving on to the next step.

    - We use `dpdk/` submodule as our DPDK driver. FYI, you can pass a different
      dpdk source directory as command line argument.

3. Bring the dpdk compatible interfaces up, and
   then set RTE_SDK and RTE_TARGET environment variables. If you are using Intel
   NICs, the interfaces will have dpdk prefix.

     ```bash
    sudo ifconfig dpdk0 x.x.x.x netmask 255.255.255.0 up
    export RTE_SDK=`echo $PWD`/dpdk
    export RTE_TARGET=x86_64-native-linuxapp-gcc
     ```

4. Setup mtcp library:

    ```bash
    ./configure --with-dpdk-lib=$RTE_SDK/$RTE_TARGET
   	make
    ```

    - By default, mTCP assumes that there are 16 CPUs in your system.
      You can set the CPU limit, e.g. on a 32-core system, by using the following command:

        ```bash
        ./configure --with-dpdk-lib=$RTE_SDK/$RTE_TARGET CFLAGS="-DMAX_CPUS=32"
        ```
    Please note that your NIC should support RSS queues equal to the MAX_CPUS value
    (since mTCP expects a one-to-one RSS queue to CPU binding).
    
    - In case `./configure` script prints an error, run the
      following command; and then re-do step-4 (configure again):
        ```bash
        autoreconf -ivf
        ```
   
    - checksum offloading in the NIC is now ENABLED (by default)!!!
        - this only works for dpdk at the moment
        - use ```./configure --with-dpdk-lib=$RTE_SDK/$RTE_TARGET --disable-hwcsum``` to disable checksum offloading.
    - check `libmtcp.a` in `mtcp/lib`
    - check header files in `mtcp/include`
    - check example binary files in `apps/example`

5. Check the configurations in `apps/example`
   - `epserver.conf` for server-side configuration
   - `epwget.conf` for client-side configuration
   - you may write your own configuration file for your application

6. Run the applications!

7. You can revert back all your changes by running the following script.

    ```bash
    ./setup_linux_env.sh [<path to $RTE_SDK>]
    ```
   
    - Press [29] to unbind the Ethernet ports
    - Press [30] to remove igb_uio.ko driver
    - Press [33] to remove hugepage mappings
    - Press [34] to quit the tool


### ***PSIO VERSION***

1. make in io_engine/driver:

    ```bash
    make
    ```

    - check ps_ixgbe.ko
    - please note that psio only runs on linux-2.6.x kernels
      (linux-2.6.32 ~ linux-2.6.38)

2. install the driver:
   
   ```bash
   ./install.py <# cores> <# cores>
   ```

    - refer to http://shader.kaist.edu/packetshader/io_engine/
    - you may need to change the ip address in install.py:46

3. Setup mtcp library:
   
    ```bash
    ./configure --with-psio-lib=<$path_to_ioengine>
    # e.g. ./configure --with-psio-lib=`echo $PWD`/io_engine
    make
    ```

    - By default, mTCP assumes that there are 16 CPUs in your system.
      You can set the CPU limit, e.g. on a 8-core system, by using the following command:

        ```bash
        ./configure --with-psio-lib=`echo $PWD`/io_engine CFLAGS="-DMAX_CPUS=8"
        ```
    
    Please note that your NIC should support RSS queues equal to the MAX_CPUS value
    (since mTCP expects a one-to-one RSS queue to CPU binding).

    - In case `./configure` script prints an error, run the
      following command; and then re-do step-3 (configure again):

        ```bash
        autoreconf -ivf
        ```

    - check `libmtcp.a` in `mtcp/lib`
    - check header files in `mtcp/include`
    - check example binary files in `apps/example`

4. Check the configurations in `apps/example`
   - `epserver.conf` for server-side configuration
   - `epwget.conf` for client-side configuration
   - you may write your own configuration file for your application

5. Run the applications!


### ***ONVM VERSION***

***NEW***: Now you can run mTCP applications (server + client) locally.
A local setup is useful when only 1 machine is available for the experiment. 
ONVM configurations are placed as `.conf` files in apps/example directory.
ONVM basics are explained in https://github.com/sdnfv/openNetVM.

**Before running the applications make sure that onvm_mgr is running.**  
*Also, no core overlap between applications and onvm_mgr is allowed.*

1. [Install openNetVM following these instructions](https://github.com/sdnfv/openNetVM/blob/master/docs/Install.md)

2. Set up the dpdk interfaces:

    ```bash
	./setup_mtcp_onvm_env.sh
    ```

3. Next bring the dpdk-registered interfaces up. This can be setup using:  

    ```bash
    sudo ifconfig dpdk0 x.x.x.x netmask 255.255.255.0 up
    ```

4. Setup mtcp library
    ```bash
    ./configure --with-dpdk-lib=$<path_to_dpdk> --with-onvm-lib=$<path_to_onvm_lib>
    # e.g. ./configure --with-dpdk-lib=$RTE_SDK/$RTE_TARGET --with-onvm-lib=`echo $ONVM_HOME`/onvm
    make
    ```

    - By default, mTCP assumes that there are 16 CPUs in your system.
    You can set the CPU limit, e.g. on a 32-core system, by using the following command:
    
        ```bash
        ./configure --with-dpdk-lib=$RTE_SDK/$RTE_TARGET --with-onvm-lib=$<path_to_onvm_lib> CFLAGS="-DMAX_CPUS=32"
        ```

    Please note that your NIC should support RSS queues equal to the MAX_CPUS value
    (since mTCP expects a one-to-one RSS queue to CPU binding).
    
    - In case `./configure` script prints an error, run the
    following command; and then re-do step-4 (configure again):
    
        ```bash
        autoreconf -ivf
        ```

    - checksum offloading in the NIC is now ENABLED (by default)!!!
    - this only works for dpdk at the moment
    - use ```./configure --with-dpdk-lib=$RTE_SDK/$RTE_TARGET --with-onvm-lib=$<path_to_onvm_lib> --disable-hwcsum``` to disable checksum offloading.
    - check `libmtcp.a` in `mtcp/lib`
    - check header files in `mtcp/include`
    - check example binary files in `apps/example`

5. Check the configurations in `apps/example`
   - `epserver.conf` for server-side configuration
   - `epwget.conf` for client-side configuration
   - you may write your own configuration file for your application

6. Run the applications!

7. You can revert back all your changes by running the following script.

    ```bash
    ./setup_linux_env.sh
    ```
   
    - Press [29] to unbind the Ethernet ports
    - Press [30] to remove igb_uio.ko driver
    - Press [33] to remove hugepage mappings
    - Press [34] to quit the tool

**Notes**

Once you have started onvm_mgr, sometimes an mTCP application may fail to get launched due
to an error resembling the one mentioned below:

- ```EAL: FATAL: Cannot init memory```
- ``` Cannot mmap memory for rte_config at [0x7ffff7fb6000], got [0x7ffff7e74000] - please use '--base-virtaddr' option```
- ```EAL: Cannot mmap device resource file /sys/bus/pci/devices/0000:06:00.0/resource3 to address: 0x7ffff7ff1000```

To prevent this, use the base virtual address parameter to run the ONVM manager (core list arg `0xf8` isn't actually used by mtcp NFs but is required), e.g.:

```bash
cd openNetVM/onvm  
./go.sh 1,2,3 1 0xf8 -s stdout -a 0x7f000000000 
```

### ***NETMAP VERSION***

See README.netmap for details.


## Tested environments

mTCP runs on Linux-based operating systems (2.6.x for PSIO) with generic 
x86_64 CPUs, but to help evaluation, we provide our tested environments 
as follows.

    Intel Xeon E5-2690 octacore CPU @ 2.90 GHz 32 GB of RAM (4 memory channels)
    10 GbE NIC with Intel 82599 chipset (specifically Intel X520-DA2)
    Debian 6.0.7 (Linux 2.6.32-5-amd64)

    Intel Core i7-3770 quadcore CPU @ 3.40 GHz 16 GB of RAM (2 memory channels)
    10 GbE NIC with Intel 82599 chipset (specifically Intel X520-DA2)
    Ubuntu 10.04 (Linux 2.6.32-47)

Event-driven PacketShader I/O engine (extended io_engine-0.2)

- PSIO is currently only compatible with Linux-2.6.

We tested the DPDK version (polling driver) with Linux-3.13.0 kernel.

## Notes

1. mTCP currently runs with fixed memory pools. That means, the size of
   TCP receive and send buffers are fixed at the startup and does not 
   increase dynamically. This could be performance limit to the large 
   long-lived connections. Be sure to configure the buffer size 
   appropriately to your size of workload.

2. The client side of mTCP supports mtcp_init_rss() to create an 
   address pool that can be used to fetch available address space in 
   O(1). To easily congest the server side, this function should be 
   called at the application startup.

3. The supported socket options are limited for right now. Please refer 
   to the mtcp/src/api.c for more detail.

4. The counterpart of mTCP should enable TCP timestamp.

5. mTCP has been tested with the following Ethernet adapters:

    1. Intel-82598       ixgbe          (Max-queue-limit: 16)
    2. Intel-82599       ixgbe          (Max-queue-limit: 16)
    3. Intel-I350        igb            (Max-queue-limit: 08)
    4. Intel-X710        i40e           (Max-queue-limit: ~)
    5. Intel-X722        i40e           (Max-queue-limit: ~)
 
## Frequently asked questions

1. How can I quit the application?
    - Use ^C to gracefully shutdown the application. Two consecutive 
    ^C (separated by 1 sec) will force quit.

2. My application doesn't use the address specified from ifconfig.
    - For some Linux distros(e.g. Ubuntu), NetworkManager may re-assign
    a different IP address, or delete the assigned IP address.

    - Disable NetworkManager temporarily if that's the case.
    NetworkManager will be re-enabled upon reboot.

     ```bash
    sudo service network-manager stop
     ```

3. Can I statically set the routing or arp table?
    - Yes, mTCP allows static route and arp configuration. Go to the 
    config directory and see sample_route.conf or sample_arp.conf. 
    Copy and adapt it to your condition and link (ln -s) the config 
    directory to the application directory. mTCP will find 
    config/route.conf and config/arp.conf for static configuration.

## Caution

1. Do not remove I/O driver (```ps_ixgbe/igb_uio```) while running mTCP 
   applications. The application will panic!

2. Use the ps_ixgbe/dpdk driver contained in this package, not the one 
   from some other place (e.g., from io_engine github).

## Contacts

GitHub issue board is the preferred way to report bugs and ask questions about mTCP.

***CONTACTS FOR THE AUTHORS***

    User mailing list <mtcp-user at list.ndsl.kaist.edu>
    EunYoung Jeong <notav at ndsl.kaist.edu>
    M. Asim Jamshed <ajamshed at ndsl.kaist.edu>
