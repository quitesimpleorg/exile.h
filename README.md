qssb.h (quite simple sandbox)
=============================
qssb.h is a simple header only library that provides an interface
to sandbox applications. Using Seccomp and Linux Namespaces for that
purpose requires some knowledge of annoying details which this library
aims to abstract away as much as possible.

Status
======
No release yet, API is unstable.

Features
========
Systemcall filtering, restricting file system access, dropping
privileges, isolating the application from the network, etc.

Requirements
============
Kernel >=3.17
sys/capabilities.h header. Depending on your system, libcap
might be needed for this.



FAQ
===

Does the process need to be priviliged to utilize the library?
----------------------------------------------------------------
No.

It doesn't work on Debian!
--------------------------
You can thank a Debian-specific patch for that. In the future,
the library may check against that. Execute
echo 1 > /proc/sys/kernel/unprivileged_userns_clone to disable that
patch for now.

Documentation
=============
To be written

Examples
========
Real world project: cgit sandboxed: https://git.quitesimple.org/cgitsb


Contributing
============
Contributions are very welcome. Options: 
1) Pull-Request: github.com/quitesimpleorg/qssb 
2) Mail to qssb at quitesimple.org with instructions
on where to pull the changes.
3) Mailing a classic patch.

License
=======
ISC

