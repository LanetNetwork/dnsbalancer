dnsbalancer
===========

Description
-----------

Daemon to balance UDP DNS requests over DNS servers.

Principles
----------

dnsbalancer daemon serves as UDP DNS load-balancing proxy between multiple
DNS clients and several DNS servers. Here is DNS packet lifecycle:

1. client creates DNS query and sends it to dnsbalancer;
2. dnsbalancer accepts incoming UDP packet and finds appropriate backend server
for it;
3. then UDP packet is parsed into ldns\_pkt structure, and if it is not valid
DNS packet, dnsbalancer silently drops it;
4. if, otherwise, accepted UDP packet is valid DNS query, dnsbalancer extracts
query information from it and checks request against ACL;
5. if packet passes ACL, dnsbalancer stores it in internal request table along
with client socket information;
6. then DNS packet with substituted ID is sent to selected forwarder;
7. when the forwarder sends reply back, dnsbalancer accepts it first;
8. then dnsbalancer parses received answer into ldns\_pkt structure, dropping
invalid packets;
9. to select client to forward answer to, dnsbalancer retrieves original query ID
from request table along with appropriate client socket;
10. finally, dnsbalancer sends answer to client and removes request from request table.

Meanwhile, garbage collector thread works, and if request table contains too old records,
they are removed periodically. Almost all the errors are silently ignored (but wisely
handled through error paths), and statistic info is updated appropriately.

To avoid 2^16 concurrent requests limit, request table consists of collision buckets.
If there are 2 or more requests sent to forwarder with the same ID, they are stored
in linked list. To speed up linked list lookup under high load, xxHash of DNS
data is used.

Configuration
-------------

dnsbalancer uses INI-style configuration file to set up frontends and backends.
Here is an example with default values:

```ini
[general]
rlimit=32768
request_ttl=10000
gc_interval=1000
watchdog_interval=1000
frontends=fe_dns

[stats]
enabled=1
layer3=ipv4
bind=127.0.0.1
port=8083

[fe_dns]
workers=-1
dns_max_packet_length=4096
layer3=ipv4
bind=127.0.0.1
port=53
backend=be_dns
acl=local/acl_1

[acl_1]
allow_all=ipv4/0.0.0.0/0/regex/list_all/allow/null

[list_all]
0=all/^.*$

[be_dns]
mode=rr
forwarders=frw_google_1,frw_google_2

[frw_google_1]
layer3=ipv4
host=8.8.8.8
port=53
check_attempts=3
check_timeout=500
check_query=. IN SOA
weight=1

[frw_google_2]
layer3=ipv4
host=8.8.4.4
port=53
check_attempts=3
check_timeout=500
check_query=. IN SOA
weight=1

```

`general` section holds common parameters and comma-delimited list of frontends:

* `rlimit` specifies file descriptors count (RLIMIT\_NOFILE) for current dnsbalancer instance;
* `request_ttl` specifies request TTL in milliseconds; usually, 10 seconds is more than enough
as normal DNS forwarders should answer within 200 ms; specifying small values could result
in eliminating RAM usage but also in query drops;
* `gc_interval` specifies GC invocation interval in milliseconds; GC (garbage collector) is a timer
thread that does cleaning up request table for orphaned (stalled) items (DNS requests that are lost
by underlying forwarders); if balancer should serve very high load, you may try to increase this value;
* `watchdog_interval` specifies watchdog invocation interval in milliseconds; it is a timer
thread that does polling forwarders.

`stats` section holds statistics options:

* `enabled` specifies whether stats should be served via built-in HTTP server;
* `layer3` specifies either IPv4 or IPv6 should be used to serve balancer stats via HTTP;
* `bind` specifies local network interface address to serve stats from;
* `port` specifies HTTP port for serving balancer stats; you may query balancer for frontends
and forwarders statistics via URL like `http://ip:port/stats`.

`frontend_name` sections hold frontend-specific data:

* `workers` specifies working threads count; -1 enables CPUs count autodetection;
* `dns_max_packet_length` specifies maximum DNS packet size; usually, 4096 is enough for everybody,
but you may also want to specify 512 as it should work almost for all configurations;
* `layer3` specifies either IPv4 or IPv6 to use for frontend connection;
* `bind` specifies local network interface address to bind to;
* `port` specifies port which frontend should listen on;
* `backend` specifies backend name;
* `acl` specifies ACL to check queries to frontend against (see below).

ACL name has the following syntax: `source/name`, where source is `local`
only for now to load ACL from config file.

`backend_name` section holds backend-specific options:

* `mode` specifies balancing mode (see details below);
* `forwarders` holds comma-delimited list of DNS forwarders.

Possible balancing modes are:

* `rr` (round-robing);
* `random` (pseudo-random);
* `least_pkts` (choosing forwarder that has accepted least packets);
* `least_traffic` (choosing forwarder that has accepted least bytes);
* `hash_l3` (choosing based on client address hash);
* `hash_l4` (choosing based on client port hash);
* `hash_l3+l4` (choosing based on client address+port hash).

`forwarder_name` section holds forwarder connection info:

* `layer3` specifies either IPv4 or IPv6 to use for forwarder connection (you may use IPv4 for frontend
and IPv6 for backend or vice-versa with no problems);
* `host` (obviously) is DNS server host;
* `port` (surprisingly) is DNS server port;
* `check_attempts` specifies check attempts made before marking forwarder as unavailable;
default value (3) should be OK for everyone, but if your forwarders are connected to unreliable channel,
try to set this value to something bigger (for example, 5);
* `check_timeout` specifies timeout of each forwarder check in milliseconds; usually, any normal
forwarder should answer within 200 ms, so default value (500 ms) should be OK almost for everyone;
however, if ping to your forwarder is high enough, consider enlarging this value;
* `check_query` specifies DNS query used to check forwarder availability; usually it is OK to check
SOA record for root zone, but it may be good idea to check SOA or A (or AAAA) of some important zone;
* `weight` specifies relative weight of current forwarder: the more value is, the more times forwarder
is being used (currently applies only to random selection mode).

### ACLs

Frontends use ACLs to check incoming queries (see ACL example above). ACLs are defined in separate
INI sections and have the following syntax:

```ini
[acl_name]
some_comment=layer3_protocol/netaddress/netmask/matcher/listname/action/actionparameters
```

That means:

* `some_comment` is usually current ACL step custom name;
* `layer3_protocol` specifies how `netaddress` and `netmask` should be interpreted (valid values are:
`ipv4` and `ipv6`);
* `netaddress` and `netmask` specifies hosts that are subjected to current ACL step (please note that
network mask is specified as decimal prefix like /0 or /24);
* `matcher` is one of the following FQDN matcher: `strict` that matches the whole FQDN strictly (fastest one),
`subdomain` that matches FQDN with all its subdomains and `regex` that matches FQDN against specified regex
(slowest one);
* `listname` is the name of DNS requests list;
* `action` is, naturally, an action performed against query in question (see below);
* `actionparameters` contains parameters to some actions (see below) or `null`;

Currently valid action values are:

* `allow` accepts query;
* `deny` silently drops query;
* `nxdomain` sends NXDOMAIN back to client;
* `set_a` sets specific IPv4 address and comma-separated TTL (via `actionparameters` field)
for immediate response.

ACL is examined step-by-step. Default ACL policy is to accept all queries.

DNS requests list has the following syntax:

`some_comment=rr_type/fqdn`

* `some_comment` is item custom name;
* `rr_type` is DNS RR type or `all` to match all types; supported values: `all`, `any`;
* `fqdn` is FQDN or regex.

Example:

```ini
[list_block_any]
0=any/^.*$
```

This will block all IN ANY requests.

Finally, one may examine ACL stats via following URL:

`http://ip:port/acl`

Remember to enable stats (see description above).

Compiling
---------

### Prerequisites

* Linux v3.9+ (for SO\_REUSEPORT, tested with 3.10+)
* cmake (tested with 2.8.11, 3.5.2)
* make (tested with GNU Make 3.82, 4.2.1)
* gcc (tested with 4.8.5, 6.1.1), clang (tested with 3.8.0) or icc (tested with 16.0.3)
* libbsd (tested with 0.6.0, 0.8.3)
* LDNS (tested with 1.6.16, 1.6.17)
* libmicrohttpd (tested with 0.9.33, 0.9.49)
* libunwind (tested with 1.1)

### Compiling

Create `build` folder, chdir to it, then run

`cmake ..`

or

`cmake -DCMAKE_BUILD_TYPE=Debug ..`

to build app with debug info. Then just type `make`.

Usage
-----

The following arguments are supported:

* --config=&lt;path&gt; (mandatory) specifies configuration file to use
* --pid-file=&lt;path&gt; (optional) specifies file to write daemon's PID to;
* --daemonize (optional) enables daemonization (preferred way to run on server);
* --verbose (optional) enables verbose output;
* --debug (optional) enables debug output (works only if compiled with MODE=DEBUG, otherwise does nothing);
* --syslog (optional) logs everything to syslog instead of /dev/stderr.

Typical usage:

`dnsbalancer --config=/etc/dnsbalancer/dnsbalancer.conf --verbose --syslog`

Distribution and Contribution
-----------------------------

Distributed under terms and conditions of GNU GPL v3 (only).

IniParser is licensed under terms and conditions of MIT License.

xxHash is licensed under terms and conditions of BSD 2-Clause License.

The following people are involved in development:

* Oleksandr Natalenko &lt;o.natalenko@lanet.ua&gt;

Mail them any suggestions, bugreports and comments.
