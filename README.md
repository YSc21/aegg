AEGG
----



Dependences
-----------

- angr
- pwntools

Problems
--------

- shellcode: why return address doesn't match real addrs?
    the offset of buffer which angr calculated is 21, but the real offset is 17

TODO
----

- AEGG: inputs in exploit_gen instead of paths (for fuzzing)

