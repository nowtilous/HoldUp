# HoldUp Change Log

All notable changes to this project will be documented in this file.

## [Released]
## [1.0.0] - 01-03-2019
### Added
- Added lightweight hypervisor
- Added memory separation and protection using table manipulation feature 
- Added OS independent wxecution flow feature
- Added privileged register protection feature
- Added security monitor
- Added event-driven access mitigation feature
- Added periodic security monitor feature
- Added task and module list periodic check feature
- Added function pointer validation periodic check feature

## [1.1.0] - 02-04-2019
### Added
- Added protection against abnormal tasks credential alteration
- Added protection against abnormal LKMs credential alteration
- Added Page Table Isolation (PTI) support
- Added Intel integrated graphics sleep mode support
### Changed 
- Now monitoring done by setting HW brekpoints on kernel functions.
 