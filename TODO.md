TODO
====

* known issues:
  * reload is not reliable under high load -- find out why and fix
  * wrap ini\_config calls for unification and error checking

* required enhancements:
  * core:
    * pre-3.9 Linux and non-Linux OSes:
      * replace SO\_REUSEPORT with helper thread that distributes requests
    * non-Linux OSes:
      * do not use epoll (possibly, use libuv for everything?)
  * ACLs:
    * MySQL backend

* possible enhancements:
  * estimate accumulating requests into batches and serving them together
    with small delay

