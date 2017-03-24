# Tests for ECR Bareflank Extension

## Description
Most of the testing is done from observing the debug output
on the serial console.  The tests that run in ring-3 are located
in tests/ and the ring-0 tests are kernel modules located in tests/modules/.

## Compilation
To build the userspace and kernel module tests, run

```
cd ~/hypervisor/extended_apis/tests
make
cd modules
make
```

## Running the tests
For the tests/*.sh tests, run them with ./<test>.sh.  The kernel modules
are used in conjunction with the vmconfig script and serial output.

The test for wbinvd (test_wbinvd.c) simply executes the instruction
when the module is loaded.  You can do this with trapping turned on
or off, like so (assuming the current directory is ~/hypervisor):

```
make start
./vmconfig wbinvd -f trap -c all
cd ~/hypervisor/extended_apis/tests/modules
make
sudo make load TEST=wbinvd
sudo make unload TEST=wbinvd
```

For executing wbinvd without trapping, replace
```
./vmconfig wbinvd -f trap -c all
```
with
```
./vmconfig wbinvd -f pass -c all
```
in the above sequence of commands.

The test module (test_cr4.c) for writes-to-cr4 sets the PCE bit
(bit 8) in CR4 on load, and clears the PCE bit on unload. To test
this, first run:
```
./vmconfig cr4 -f dump -c all
```
This outputs the current configuration of the guest CR4, the
CR4 read shadow, and the CR4 guest/host mask to serial for each core.
By default, the CR4 guest/host mask is 0, meaning the guest can change
values of CR4 at will.  Take note whether or not bit 8 is set
in the guest CR4 and then run the following:
```
./vmconfig cr4 -f trap -b pce -c all
```
This configures the VM to trap (by setting bit 8 of the CR4 guest/host
mask), on every core, *changes* to the PCE bit relative to the current
configuration.  So if the output from the dump above shows the PCE bit
is clear for core x, then code that sets the PCE bit will trap. If
PCE is set for core x, code that clears the PCE bit will trap.

Now run
```
cd ~/hypervisor/extended_apis/tests/modules
sudo make load TEST=cr4
./vmconfig cr4 -f dump -c all
```
If PCE was disabled originally on the core that loaded the module, then
it should be set in the guest CR4 with the CR4 guest/host mask cleared to 0.
