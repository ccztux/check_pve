# Changelog

All notable changes to this project will be documented in this file.

## [0.5.6] - 2025-08-??

### Added
- **Constants**: Added `NAGIOS_EXIT_CODES` and `BYTE_UNITS` constants for better code maintainability
- **Parameter Validation**: Added comprehensive validation for required connection parameters (`--address`, `--username`, `--password`)
- **Connection Timeout**: Added 30-second read timeout for HTTP connections
- **Error Handling**: Enhanced exception handling with specific error types:
  - `Timeout::Error` for connection timeouts
  - `Errno::ECONNREFUSED` for connection refused errors
  - `Errno::EHOSTUNREACH` for unreachable hosts
  - `OpenSSL::SSL::SSLError` for SSL connection errors
- **JSON Validation**: Added JSON parsing error handling and API response data validation
- **Data Validation**: Added `assert_required_keys!` method for checking required data fields

### Changed
- **Exit Codes**: Refactored exit codes to use named constants instead of hardcoded numbers
- **Version Variable**: Changed `version` variable to `VERSION` constant
- **Unit Conversion**: Refactored `convert_value` method to use `BYTE_UNITS` constant with cleaner case statement
- **VM Status Check**: Enhanced `vm_status` method to handle multiple VM states:
  - `running` → OK (0)
  - `stopped` → CRITICAL (2)
  - `paused` → WARNING (1)
  - Other states → CRITICAL (2) with state information

### Fixed
- **Exception Handling**: Fixed `uninitialized constant Net::TimeoutError` error by using correct `Timeout::Error`
- **SMART Status**: Fixed SMART health check logic (`item['health'] == 'OK'` instead of incorrect `'OK'`)
- **Error Messages**: Improved error messages with better context and troubleshooting information

### Technical Improvements
- **Code Structure**: Better separation of concerns with dedicated validation methods
- **Error Reporting**: More descriptive error messages for network connectivity issues
- **Robustness**: Enhanced error handling prevents script crashes on network issues
- **Maintainability**: Constants improve code readability and reduce magic numbers

### Dependencies
- No new dependencies added
- Maintains compatibility with existing Ruby standard library requirements

---

## Migration Notes

This version includes breaking changes in error handling behavior:
- Scripts that previously caught generic errors may need to be updated
- VM status checks now distinguish between stopped, paused, and unknown states
- Connection timeout errors now provide more specific error messages

For users upgrading from previous versions, no configuration changes are required.



## [0.5.5]
### other
* Rewritten to support older Ruby version (Ruby >= 2.0)

### added
* Added modes: node-cpu-load, vm-status, list-nodes, list-vms
* Added option -d, --debug to enable debug
* Added option -r, --percpu to divide load per cpu
* Added pb to units
* Added default thresholds
* Added rudimentary option checks

## [0.3.0]
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


## [0.2.5]
### fixes
* subscription: show message from json output when status is not "Active"


## [0.2.4]
### features
* new modes: ksm, net_in, net_out

### other
* smart check allows exclude option
* exclude option now uses regex


## [0.2.3]
### other
* add '-H' option for host address (!4)
* rubocop - rescue exception var name


## [0.2.2]
### features
* add an exclude option for _services_ check


## [0.2.1]
### fixes
* fix wrong var name (#1)


## [0.2]
### features
* new vm/lxc check modes


## [0.1.1]
### fixes
* smart ok output changed to 'PASSED' (!1)
