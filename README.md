qssb (quite simple sandbox)
===========================
qssb.h is a simple header only library for easy sandboxing of
applications.

It aims to provide an interface to avoid the annoying details that
using Seccomp and Linux Namespaces requires.

Features
========
Systemcall filtering, restricting file system access, dropping
privileges, isolating the application from the network, etc.

Requirements
============
Kernel x.y.z.

Status
======
No release yet, API is unstable.

Documentation
=============
To be written

Examples
========
Real world project: cgit sandboxed: https://git.quitesimple.org/cgitsb


Contributing
============
Contributations are very welcome. Options: 
1) Pull-Request: github.com/quitesimpleorg/qssb 
2) Mail to qssb at quitesimple.org with instructions
on where to pull the changes.
3) Mailing a classic patch.

License
=======
ISC

