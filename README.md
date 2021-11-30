# exile.h
`exile.h` is a simple header-only library that provides an interface to isolate processes on Linux. Using Seccomp and Linux Namespaces for that purpose requires some knowledge of annoying details which this library aims to abstract away as much as possible, when reasonable. Hence, the goal is to provide a convenient way for processes to restrict themselves in order to mitigate the effect of exploits. Currently, it utilizes technologies like Seccomp, Namespaces and Landlock to this end.

## Status
No release yet, expiremental, API is unstable, builds will break on updates of this library. 

Currently, it's mainly evolving according to the needs of my other projects. 

## Features

  - Systemcall filtering (using seccomp-bpf)
  - restricting file system access (using Landlock and/or Namespaces)
  - dropping privileges 
  - isolating the application from the network, etc.

## Requirements

Kernel >=3.17

``sys/capabilities.h`` header. Depending on your distribution, libcap
might be needed for this.

While mostly transparent to users of this API, kernel >= 5.13 is required to take advantage of Landlock.



## FAQ


### Does the process need to be priviliged to utilize the library?

No. 

### It doesn't work on Debian!

You can thank a Debian-specific kernel patch for that. In the future,
the library may check against that. Execute
`echo 1 > /proc/sys/kernel/unprivileged_userns_clone` to disable that patch for now.

### Examples
  - looqs: https://gitea.quitesimple.org/crtxcr/looqs
  - qswiki: https://gitea.quitesimple.org/crtxcr/qswiki
  - cgit sandboxed: https://gitea.quitesimple.org/crtxcr/cgitsb
  - qpdfviewsb sandboxed (quick and dirty): https://gitea.quitesimple.org/crtxcr/qpdfviewsb


### Contributing

Contributions are very welcome. Options: 

1. Pull-Request on [github](https://github.com/quitesimpleorg/exile.h)
2. Mail to `exile at quitesimple.org` with instructions on where to pull the changes from.
3. Mailing a classic patch/diff to the same address.


License
=======
ISC

