# check_pve

<a href="https://coindrop.to/marcopeterseil" target="_blank"><img src="https://coindrop.to/embed-button.png" style="border-radius: 10px; height: 57px !important;width: 229px !important;" alt="Coindrop.to me"></img></a> Support goes 100% to [local animal hospice](https://www.animal-spirit.at/)

[Proxmox Virtual Environment](https://www.proxmox.com/en/proxmox-ve) Naemon/Icinga/Nagios plugin which checks various stuff via Proxmox API(v2).

[[_TOC_]]

## Requirements

### Ruby
* Ruby >2.3

### PVE
A user/role with appropriate rights. See [User Management](https://pve.proxmox.com/wiki/User_Management) for more information.
```shell
# /etc/pve/user.cfg
user:monitoring@pve:1:0::::::

role:PVE_monitoring:Datastore.Audit,Sys.Audit,Sys.Modify,VM.Audit:
acl:1:/:monitoring@pve:PVE_monitoring:
```

#### How to add user and role
```shell
pveum useradd monitoring@pve -comment "Monitoring User"
pveum passwd monitoring@pve
pveum roleadd PVE_monitoring -privs "Datastore.Audit,Sys.Audit,Sys.Modify,VM.Audit"
pveum aclmod / -user monitoring@pve -role PVE_monitoring
```

## Usage
```shell
check_pve v0.3.0 [https://gitlab.com/6uellerBpanda/check_pve]

This plugin checks various parameters of Proxmox Virtual Environment via API(v2)

Mode:
  Cluster:
    cluster-status            Checks quorum of cluster
  Node:
    node-smart-status          Checks SMART health of disks
    node-updates-available     Checks for available updates
    node-subscription-valid    Checks for valid subscription
    node-services-status       Checks if services are running
    node-task-errors           Checks for task errors
    node-storage-usage         Checks storage usage in percentage
    node-storage-status        Checks if storage is online/offline
    node-cpu-usage             Checks CPU usage in percentage
    node-memory-usage          Checks Memory usage in percentage
    node-io-wait               Checks IO wait in percentage
    node-net-in-usage          Checks inbound network usage
    node-net-out-usage         Checks outbound network usage
    node-ksm-usage             Checks KSM sharing usage
  VM:
    vm-cpu-usage               Checks CPU usage in percentage
    vm-memory-usage            Checks memory usage in percentage
    vm-disk-read-usage         Checks how much last 60s was read (timeframe: hour)
    vm-disk-write-usage        Checks how much last 60s was written (timeframe: hour)
    vm-net-in-usage            Checks incoming usage from last 60s (timeframe: hour)
    vm-net-out-usage           Checks outgoing usage from last 60s (timeframe: hour)

Usage: check_pve.rb [mode] [options]

Options:
    -s, -H, --address ADDRESS        PVE host address
    -k, --insecure                   No SSL verification
    -m, --mode MODE                  Mode to check
    -n, --node NODE                  PVE Node name
    -u, --username USERNAME          Username with auth realm e.g. monitoring@pve
    -p, --password PASSWORD          Password
    -w, --warning WARNING            Warning threshold
    -c, --critical CRITICAL          Critical threshold
        --unit UNIT                  Unit - kb, mb, gb, tb
        --name NAME                  Name for storage or user filter for tasks
    -i, --vmid VMID                  ID of qemu/lxc machine
    -t, --type TYPE                  VM type lxc, qemu or type filter for tasks
    -x, --exclude EXCLUDE            Exclude (regex)
        --timeframe TIMEFRAME        Timeframe for vm checks: hour,day,week,month or year
        --cf CONSOLIDATION_FUNCTION  RRD cf: average or max
        --lookback LOOKBACK          Lookback in seconds
    -v, --version                    Print version information
    -h, --help                       Show this help message
```
### Options
* -s, -H: PVE host address, only https supported, e.g. _pve-01.example.com_

* -k: Don't validate certificate

* -m: check to be used (node-cluster-status,..)

* -n: PVE Node name

* -u: Username with auth realm, e.g. _monitoring@pve_, _root@pam_

* -i: ID of qemu/lxc machine

* -x: Exclude items (regex)

* --name: Storage name, e.g. _local_, _local-lvm_, also used as user filter for tasks

* --type: either lxc or qemu, also used as type filter for tasks

* --timeframe: time frame for rrd data; _hour, day, week, month_ or _year_. Default 'hour'

* --cf: consolidation function for rrd data; _average_ or _max_. Default 'max'

* --lookback: time in seconds to look back

* --unit: specify desired unit output: kb, mb, gb, tb. Default 'mb'

## Modes
### Cluster
Checks if the cluster is quorate. Warning if not. (/cluster/status)

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -m cluster-status
OK - LNZ: Cluster ready - quorum is ok
```

### Node
The node name (via -n option) is required for all node checks.

#### SMART
Checks SMART status of the disks. (/nodes/{node}/disks/list)

Allows exclude option: `--exclude '^/dev/sda'`

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-smart-status
OK - No SMART errors detected
```

#### Updates
Displays a warning if new updates are available. (/nodes/{node}/apt/update)

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-updates-available
Warning - 12 updates available
```

#### Subscription
Checks if subscription is valid. (/nodes/{node}/subscription)

Specify warning threshold for minimum number of days subscription has to be valid.
Critical status if the subscription has expired.

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-subscription-valid -w 60                                                 
Warning - Subscription will end at 2018-10-13
```

#### Services
Displays a warning if a service isn't running. (/nodes/{node}/services)

Allows exclude option: `--exclude 'ksmtuned'`

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-services-status
Warning - postfix, spiceproxy not running
```
To exclude services:

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-services-status -x 'postfix|spiceproxy'
OK - All services running
```

#### Tasks
Displays a warning if failed [tasks](https://pve.proxmox.com/pve-docs/chapter-sysadmin.html#_task_history) occurred. (/nodes/{node}/tasks)

Specify `--lookback` option in seconds to check from the current time.

With `--name` and `--type` user and type filter can be specified.

Exclude option `--exclude` can specified for the status message.

```shell
# only show errors from shutdown tasks the last hour
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-task-errors --lookback 3600 -t qmshutdown
Warning - 2022-07-24 14:20:08 +0200: qmshutdown/root@pam - received interrupt

# but exclude tasks with 'interrupt' in the status message
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-task-errors --lookback 3600 -t qmshutdown -x 'interrupt'
OK - No failed tasks
```

#### Storage

##### Usage
Checks storage usage in percentage. Value will be rounded. (/nodes/{node}/storage/{storage}/status)

Specify datastore/storage with `--name` option.


```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-storage-usage --name local -w 40 -c 60
Warning - Storage usage: 45% | Usage=45%;40;60
```

##### Status
Checks the status (online/offline) of all enabled storages on the node. (/nodes/{node}/storage/{storage})

Allows exclude option.

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-storage-status
Warning - local-lvm not active
```

#### CPU
Checks CPU usage in percentage. Value will be rounded. (/nodes/{node}/status)

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-cpu-usage -w 40 -c 60
OK - CPU usage: 30% | Usage=1%;40;60
```

#### Memory
Checks memory usage in percentage. Value will be rounded. (/nodes/{node}/status)

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-memory-usage -w 90 -c 95
OK - Memory usage: 85.03% | Usage=85.03%;90;95
```

#### IO Wait
Checks IO wait/delay usage in percentage. Value will be rounded. (/nodes/{node}/status)

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-io-wait -w 1 -c 3
OK - IO Wait: 0% | Wait=0%;1;3
```

#### Network usage
Checks network usage (In/Out). Value will be rounded. (/nodes/{node}/rrddata)

```shell
# inbound
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-net-in-usage -w 100 -c 200
OK - Network usage in: 2.54MB | Usage=2.54MB;100;200
# outbound
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-net-out-usage -w 100 -c 200
OK - Network usage out: 1.12MB | Usage=1.12MB;100;200
```

#### KSM
Checks KSM usage. Value will be rounded. (/nodes/{node}/status)

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m node-ksm-usage --unit gb -w 20 -c 25
OK - KSM sharing: 14.26GB | Usage=14.26GB;20;25
```

### VM
QEMU/KVM and LXC are supported.

Following options are necessary for all vm checks:
* _node (-n)_
* _type (--type)_
* _vmid (-i)_

> __Note:__ These checks are parsing the rrddata from pve and do not reflect the actual data when the check has been run. It will always use the last item in the rrddata array.
> Example: If you specify timeframe hour and disk read check it will display how much read io (kb) was done in the last 60s.

#### CPU
Check CPU usage in percentage. Value will be rounded. (/nodes/{node}/{type}/{vmid}/rrddata)

```shell
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m vm-cpu-usage -t qemu -i 126 -w 80 -c 90
OK - CPU usage: 5% | Usage=5%;80;90
```

#### Disk read, write
Checks how much read/write io was done. Value will be rounded. (/nodes/{node}/{type}/{vmid}/rrddata)

```shell
# read
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m vm-disk-read-usage -t qemu -i 126 -w 80 -c 90
OK - Disk read: 2MB | Usage=2MB;80;90
# write
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m vm-disk-write-usage -t qemu -i 126 -w 80 -c 90
OK - Disk write: 15.4MB | Usage=15.4MB;80;90
```

#### Network usage
Checks how much incoming/outgoing network traffic was done in kb. Value will be rounded. (/nodes/{node}/{type}/{vmid}/rrddata)

```shell
# read
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m vm-net-in-usage -t qemu -i 126 -w 50 -c 60
OK - Network usage in: 2.45MB | Usage=2.45MB;50;60
# write
./check_pve.rb -s pve.example.com -u monitoring@pve -p test1234 -n pve -m vm-net-out-usage -t qemu -i 126 -w 50 -c 60
OK - Network usage out: 1.1MB | Usage=1.1MB;50;60
```
