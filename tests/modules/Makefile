

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

endif
