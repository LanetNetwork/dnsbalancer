[![Build Status](https://travis-ci.org/pfactum/dnsbalancer.svg?branch=v0.2.x)](https://travis-ci.org/pfactum/dnsbalancer)

dnsbalancer
===========

Description
-----------

Daemon to balance UDP DNS requests over DNS servers.

Principles
----------

TBD.

Building
--------

### Prerequisites

* `Linux kernel` v4.5+ (with `SO_REUSEPORT` and `EPOLLEXCLUSIVE` support, tested with v4.13)
* `gcc` (tested with v7.2.0), `clang` (tested with v5.0.0) or `icc` (tested with v18.0.0)
* `pkg-config` (tested with v0.29.2)
* `cmake` (tested with v3.9.5)
* `ninja` (tested with v1.8.2) or `make` (tested with v4.2.1)
* `LDNS` (tested with v1.7.0)
* `libunwind` (tested with v1.2.1)
* `libini_config` (tested with v1.3.0)
* `libtcmalloc_minimal` (optional, tested with v2.5)
* `libatomic_ops` (optional, required if only compiler does not support atomics, tested with v7.4.6)

### Compiling

Create `build` folder, chdir to it, then run

`cmake -G Ninja ..`

or

`cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug ..`

to build app with debug info. Then just type `cmake --build .`.

Configuration
-------------

TBD.

### ACLs

TBD.

Usage
-----

TBD.

Distribution and Contribution
-----------------------------

Distributed under terms and conditions of GNU GPL v3 (only).

Developers:

* Oleksandr Natalenko &lt;oleksandr@natalenko.name&gt;
