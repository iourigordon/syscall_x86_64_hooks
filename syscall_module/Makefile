ifneq ($(KERNELRELEASE),)
	obj-m := syscall_hooks.o
	syscall_hooks-objs:= syscall.o register_hook.o \
                         map_64_idx.o map_32_idx.o \
                         hooks_64.o hooks_32.o \
                         page_access.o utils.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
endif
