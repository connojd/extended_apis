

ifneq ($(KERNELRELEASE),)
	obj-m := test_wbinvd.o test_cr4.o
else
	PWD:=$(shell pwd)

all:
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) clean

load:
	insmod ./test_$(TEST).ko

unload:
	rmmod ./test_$(TEST).ko

help:
	@echo "make                            - build kernel modules"
	@echo "make clean                      - remove build files"
	@echo "sudo make load TEST=<test>.ko   - load kernel module test_<test>.ko"
	@echo "sudo make unload TEST=<test>.ko - unload kernel module test_<test>.ko"
	@echo "make help                       - print this help"
endif
