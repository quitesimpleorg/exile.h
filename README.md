# exile.h
`exile.h` is a header-only library, enabling processes to easily isolate themselves on Linux for exploit mitigation purposes. exile.h wants to make existing technologies, such as Seccomp and Linux Namespaces, easier to use. Those generally
require knowledge of details and are not trivial for developers to employ, which prevents a more widespread adoption.

The following section offers small examples. Then the motivation is explained in more detail.
Proper API documentation will be maintained in other files.

## Quick demo
This section quickly demonstrates the simplicity of the API. It serves as an overview to get
a first impression.

system() is used to keep the example C code short. It also demonstrates that subprocesses are also subject to restrictions imposed by exile.h.

While the example show different features separately, it is generally possible to combine those.

### Filesystem isolation
```c
#include "exile.h"
#include <assert.h>
int main(void)
{
	system("echo test > /home/user/testfile");
	struct exile_policy *policy = exile_init_policy();
	exile_append_path_policies(policy, EXILE_FS_ALLOW_ALL_READ, "/home/user");
	exile_append_path_policies(policy, EXILE_FS_ALLOW_ALL_READ | EXILE_FS_ALLOW_ALL_WRITE, "/tmp");
	int ret = exile_enable_policy(policy);
	if(ret != 0)
	{
		exit(EXIT_FAILURE);
	}
	int fd = open("/home/user/test", O_CREAT | O_WRONLY | O_TRUNC, 0600);
	assert(fd == -1);
	fd = open("/home/user/testfile", O_RDONLY);
	//use fd
	assert(fd != -1);
	fd = open("/tmp/testfile", O_CREAT | O_WRONLY | O_TRUNC, 0600);
	//use fd
	assert(fd != -1);
	return 0;
}
```

The assert() calls won't be fired, consistent with the policy.

### System call policies / vows
exile.h allows specifying which syscalls are permitted or denied. In the folloing example,
ls is never executed, as the specificed "vows" do not allow the execve() system call. The
process will be killed.

```c
#include "exile.h"

int main(void)
{
	struct exile_policy *policy = exile_init_policy();
	policy->vow_promises = exile_vows_from_str("stdio rpath wpath cpath");
	exile_enable_policy(policy);
	printf("Trying to execute...");
	execlp("/bin/ls", "ls", "/", NULL);
}
```

### Isolation from network
exile offers a quick way to isolate a process from the default network namespace.

```c
#include "exile.h"

int main(void)
{
	struct exile_policy *policy = exile_init_policy();
	policy->namespace_options |= EXILE_UNSHARE_NETWORK;
	int ret = exile_enable_policy(policy);
	if(ret != 0)
	{
		exit(EXIT_FAILURE);
	}
	system("curl -I https://evil.tld");
}
```
Produces ```curl: (6) Could not resolve host: evil.tld```. For example, this is useful for subprocesses which do not need
network access, but perform tasks such as parsing user-supplied file formats.

### Isolation of single functions
Currently, work is being done that hopefully will allow isolation of individual function calls in a mostly pain-free manner.

Consider the following C++ code:
```cpp
#include <iostream>
#include <fstream>
#include "exile.hpp"
std::string cat(std::string path)
{
	std::fstream f1;
	f1.open(path.c_str(), std::ios::in);
	std::string content;
	std::string line;
	while(getline(f1, line)) {
		content += line + "\n";
	}
	return content;
}

int main(void)
{
	struct exile_policy *policy = exile_init_policy();
	policy->vow_promises = exile_vows_from_str("stdio rpath");

	std::string content = exile_launch<std::string>(policy, cat, "/etc/hosts");
	std::cout << content;

	policy = exile_init_policy();
	policy->vow_promises = exile_vows_from_str("stdio");

	try
	{
	content = exile_launch<std::string>(policy, cat, "/etc/hosts");
	std::cout << content;
	}
	catch(std::exception &e)
	{
		std::cout << "launch failure: " << e.what() << std::endl;
	}
}
```

We execute "cat()". The first call succeeds. In the second, we get an exception, because
the subprocess "cat()" was launched in violated the policy (missing "rpath" vow). 

Naturally, there is a performance overhead. Certain challenges such pass-by-reference
are yet to be solved.

## Status
No release yet, experimental, API is unstable, builds will break on updates of this library.

Currently, it's mainly evolving from the needs of my other projects.

## Motivation and Background
exile.h unlocks existing Linux mechanisms to facilite isolation of processes from resources. Limiting the scope of what programs can do helps defending the rest of the system when a process gets under attacker's control (when classic mitigations such as ASLR etc. failed). To this end, OpenBSD has the pledge() and unveil() functions available. Those functions are helpful mitigation mechanisms, but such accessible ways are unfortunately not readily available on Linux. This is where exile.h steps in.

Seccomp allows restricting the system calls available to a process and thus decrease the systems attack surface, but it generally is not easy to use. Requiring BPF filter instructions, you generally just can't make use of it right away. exile.h provides an API inspired by pledge(), building on top of seccomp. It also provides an interface to manually restrict the system calls that can be issued.

Traditional methods employed to restrict file system access, like different uids/gids, chroot, bind-mounts, namespaces etc. may require administrator intervention, are perhaps only suitable
for daemons and not desktop applications, or are generally rather involved. As a positive example, Landlock since 5.13  is a vast improvement to limit file system access of processes. It also greatly simplifies exile.h' implementation of fs isolation.

Abstracting those details may help developers bring sandboxing into their applications.

## Example: Archive extraction
A programming uncompressing archives does not need network access, but should a bug allow code execution, obviously the payload may also access the network. Once the target path is known, it doesn't need access to the whole file system, only write-permissions to the target directory and read on the archive file(s).

TODO example with exile.h applied on "tar" or "unzip". Link to repo.

## Example: Web apps
Those generally don't need access to the whole filesystem hierarchy, nor do they necessarily require the ability to execute other processes.

Way more examples can be given, but we can put it in simple words: A general purpose OS allow a process to do more things than it actually needs to do.

## Features
  - Restricting file system access (using Landlock or Namespaces/chroot as fallback)
  - Systemcall filtering (using seccomp-bpf). An interface inspired by OpenBSD's pledge() is available, removing the need to specifc rules for syscalls.
  - Dropping privileges in general, such as capabilities
  - Isolating the application from the network, etc. through Namespaces
  - Helpers to isolate single functions


## What it's not
A way for end users/administrators to restrict processes. In the future, a wrapper binary may be available to achieve this, but it generally aims for developers to bring sandboxing/isolation into their software. This allows a more fine-grained approach, as the developers are more familiar with their software. Applying restrictions with solutions like AppArmor requires
them to be present and installed on the system and it's easy to break things this way.

Therefore, software should ideally be written with sandboxing in mind from the beginning.


## Documentation
Will be available once the interface stabilizes.

It's recommended to start with [README.usage.md] to get a feeling for exile.h.
API-Documentation: [README.api.md]

## Limitations
TODO:
 - seccomp must be kept up to date syscalls kernel
 - ioctl does not know the fd, so checking values is kind of strange
 - redundancies: some things are handled by capabilties, other by seccomp or both
 - seccomp no deep argument inspection
 - landlock: stat() does not apply
 - no magic, be reasonable, devs should not  get sloppy, restrict IPC.

## Requirements
Kernel >=3.17

While mostly transparent to users of this API, kernel >= 5.13 is required to take advantage of Landlock. Furthermore, it depends on distro-provided kernels being reasonable and enabling it by default. In practise, this means that Landlock probably won't be used for now, and exile.h will use a combination of namespaces, bind mounts and chroot as fallbacks.


## FAQ


### Does the process need to be priviliged to utilize the library?

No.

### It doesn't work on my Debian version!
You can thank a Debian-specific kernel patch for that. Execute
`echo 1 > /proc/sys/kernel/unprivileged_userns_clone` to disable that patch for now.

Note that newer releases should not cause this problem any longer, as [explained](https://www.debian.org/releases/bullseye/amd64/release-notes/ch-information.en.html#linux-user-namespaces) in the Debian release notes.

### Real-world usage
  - looqs: https://gitea.quitesimple.org/crtxcr/looqs
  - qswiki: https://gitea.quitesimple.org/crtxcr/qswiki

Outdated:
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

