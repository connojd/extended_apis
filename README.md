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

./tools/scripts/setup-ubuntu.sh
./configure -m ./extended_apis/bin/extended_apis.modules

make
```

Note that not all versions of each OS is supported.

## Startup / Teardown

Once the build is done, issue the following sequence of commands to load
the kernel driver and Bareflank modules, respectively:

```
make driver_load
make load
```

The kernel driver is named bareflank.ko.  Run 'dmesg' to see
the output from the make commands to ensure the load step succeeded.

Next we start the actual hypervisor:

```
make start
```

This enables VMX operation, thereby demoting the host OS to a guest. Once again, 'dmesg' is useful for debugging and ensuring this step succeeded.

You can stop and unload the hypervisor with
```
make stop
make unload
```


## Live Configuration

Live configuration is done with the config_cores script under
hypervisor/extended_apis/tools.  To use it, you may want to create a
symlink to vmconfig:
```
cd ~/hypervisor
ln -s extended_apis/tools/config_cores vmconfig
```

Executing ./vmconfig with no args will list help for the different
options. Note that the configuration code provides only a *mechanism* for
configuring the VMCS at runtime, so it won't stop you from committing
configurations that crash your box.
