WORKDIR := /media/psf/kernel_source
KERNELDIR := $(WORKDIR)/msm
PWD := $(shell pwd)
ARCH=arm
CROSS_COMPILE=$(WORKDIR)/toolchains/arm-eabi-4.8/bin/arm-eabi-
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
obj-m := REHelper.o
modules:
	$(MAKE) -C $(KERNELDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) modules  
clean:
	rm *.o *.ko *.mod.c *.order