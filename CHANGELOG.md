# changes by release
## 0.5.5
* Rewritten to support older Ruby version (Ruby >= 2.0)
* Added modes: node-cpu-load, vm-status, list-nodes, list-vms
* Added option -d, --debug to enable debug
* Added option -r, --percpu to device load per cpu when using mode node-cpu-load
* Added pb to units
* Added default thresholds
* Added rudimentary option checks

## 0.3.0
* __NOTE__ - I've renamed all checks to a more consistent syntax to distinguish them better.

### added
* node-task-errors: new mode to check for failing [tasks](https://pve.proxmox.com/pve-docs/chapter-sysadmin.html#_task_history).
* node-storage-status: new mode which checks if all enabled storages are online.
* --unit option: specify for desired unit output: mb, gb, etc. Defaults to mb.

### other
* node-services-status: shows service names in OK status output.
* node-updates-available: displays the amount of avail updates.
* node/vm-memory-usage: now uses percentage.
* --timeframe and --cf are now optional. Defaults to `--timeframe hour` and `--cf max`.

## 0.2.5
### fixes
* subscription: show message from json output when status is not "Active"

## 0.2.4
### features
* new modes: ksm, net_in, net_out

### other
* smart check allows exclude option
* exclude option now uses regex

## 0.2.3
### other
* add '-H' option for host address (!4)
* rubocop - rescue exception var name

## 0.2.2
### features
* add an exclude option for _services_ check

## 0.2.1
### fixes
* fix wrong var name (#1)

## 0.2
### features
* new vm/lxc check modes

## 0.1.1
### fixes
* smart ok output changed to 'PASSED' (!1)
