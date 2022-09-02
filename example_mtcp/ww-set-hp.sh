HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`


sudo mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages
