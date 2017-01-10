TODO
====

* known issues:
  * reload is not reliable under high load -- find out why and fix

* required enhancements:
  * core:
    * pre-3.9 Linux and non-Linux OSes:
      * replace SO\_REUSEPORT with helper thread that distributes requests
    * non-Linux OSes:
      * do not use epoll (possibly, use libuv for everything?)
  * ACLs:
    * MySQL backend
  * contribs:
    * try to get rid of all contribs:
      * xxHash:
        * fast, but maybe Open/Libre/whateverSSL could provide us with something
          fast as well
        * we de not neet cryptographic hash, but uniformly distributed hash
          that is very fast
        * do some benchmarks?
    * leave pfcq/pfpthq as it is

* possible enhancements:
  * estimate accumulating requests into batches and serving them together
    with small delay

