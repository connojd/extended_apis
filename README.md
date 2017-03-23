# ECR Bareflank Extension

## Description

This project extends the [Bareflank Hypervisor](https://github.com/Bareflank/hypervisor)'s [extended APIs](https://github.com/Bareflank/extended_apis)
to provide an interface for live configuration of the VMCS's optional
exit conditions.  This repo is part of a larger effort to research
fine-grained side-channels available to guest VMs.

## Compilation

To setup the extension, clone the ecr branch from connojd/hypervisor.git
and connojd/extended_apis.git. Find the approprate setup script for your OS
from hypervisor/tools/scripts. For example, on Ubuntu 16.10, we enter

```
cd ~/
git clone -b ecr https://github.com/connojd/hypervisor.git
cd ~/hypervisor
git clone -b ecr https://github.com/connojd/extended_apis.git

./tools/scripts/setup_ubuntu.sh --no-configure
./configure -m ./extended_apis/bin/extended_apis.modules

make
```

Note that not all versions of each OS is supported.

## Startup / Teardown

Once the build is done, enter the following to load
the kernel driver and Bareflank modules, respectively:

```
make driver_load
make load
```

The kernel driver is named bareflank.ko.  You may run 'dmesg' to see
the output from the make commands to ensure the load step succeeded.

Next we start the hypervisor:

```
make start
```

After the start step succeeds, refer to the live configuration section
below to further configure the hypervisor.  Parameters can
be tweaked in hypervisor/include/constants.h.  That file contains
the default serial parameters.  The default port is 0x3f8 with
9600 baud.

You can stop and unload the hypervisor with
```
make stop
make unload
```


## Live Configuration

Live configuration is done with the config_cores script under
hypervisor/extended_apis/tools.  To use it, create a symlink
to vmconfig:
```
cd ~/hypervisor
ln -s extended_apis/tools/config_cores vmconfig
```

Executing ./vmconfig with no args will list help for the different
options. Note that the configuration code provides only a *mechanism* for
configuring the VMCS at runtime, so it won't stop you from committing
configurations that crash your box.
