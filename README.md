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
query information from it, calculates its CRC64 and stores it in internal hash
table along with client socket information;
5. then unmodified DNS packet is sent to selected forwarder;
6. when the forwarder sends reply back, dnsbalancer accepts it first;
7. then dnsbalancer parses received answer into ldns\_pkt structure, dropping
invalid packets;
8. to select client to forward answer to, dnsbalancer must again calculate CRC64
of received answer and find appropriate client socket in hash table;
9. if there is appropriate record in hash table, dnsbalancer finds it, selects
client socket, sends answer to it and removes info about DNS packet from hash table.

Meanwhile, garbage collector thread works, and if hash table contains too old records,
they are removed periodically. Almost all the errors are silently ignored (but wisely
handled through error paths), and statistic info is updated appropriately.

Here is the list of DNS packet fields involved in CRC64 calculation:

1. DNS query ID;
2. DNS query type;
3. DNS query class;
4. DNS query FQDN.

Also, forwarder socket number is used in CRC64 calculation as well. These 5 values
are sufficient to connect DNS requests and replies unambiguously. If, however, CRC64
hash collision happens, it is handled via simple linear list under separate lock. One
may monitor hash table average load using stats served via HTTP (see below).

Hash list average load is maximum hash collision domain size happened in hash table,
averaged withing 1, 5 and 15 minutes. The lower value is, the better (1.00 is optimal but
not achievable, higher values indicate lock contention, lower, on the contrary, shows that
hash table is oversized). Try to keep hash table load average under 10.00.

Configuration
-------------

dnsbalancer uses INI-style configuration file to set up frontends and backends.
Here is an example with default values:

```ini
[general]
rlimit=32768
hashlist_size=1024
hashlist_ttl=10000
gc_interval=1000
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
* `hashlist_size` specifies the size of hashmap that holds DNS queries; specifying
big values could result in performance improvements due to narrowing hash collision domains,
however big hashlists consume more RAM; the semi-optimal value could be the average number of
concurrent items stored in hashlist (that means, the average value of concurrent DNS requests);
* `hashlist_ttl` specifies hashitem TTL in milliseconds; usually, 10 seconds is more than enough
as normal DNS forwarders should answer within 200 ms; specifying small values could result
in eliminating RAM usage but also in query drops;
* `gc_interval` specifies GC invocation interval in milliseconds; GC (garbage collector) is a timer
thread that does housekeeping work: polling forwarders as well as cleaning up hashlist for orphaned
(stalled) items (DNS requests that are lost by underlying forwarders); if balancer should serve very
high load, you may try to increase this value.

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
* `backend` specifies backend name.

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

Compiling
---------

### Prerequisites

* Linux v3.9+ (for SO\_REUSEPORT)
* cmake (tested with 2.8.11)
* make (tested with GNU Make 3.82)
* gcc (tested with 4.8.3)
* libbsd (tested with 0.6.0)
* LDNS (tested with 1.6.16)
* IniParser (tested with 3.1)
* libmicrohttpd (tested with 0.9.33)

### Compiling

First, initialize and update git submodules:

`git submodule init`
`git submodule update`

Please note, that it is possible that you will have to init and update sub-submodules
for some submodules as they depend on each other.

Then, create `build` folder, chdir to it, then run

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

The following people are involved in development:

* Oleksandr Natalenko &lt;o.natalenko@lanet.ua&gt;

Mail them any suggestions, bugreports and comments.
