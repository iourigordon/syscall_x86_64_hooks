#!/bin/bash

KERN_MODULE_DIR=syscall_module
USERLAND_TEST=syscall_user

all:
	make -C ${KERN_MODULE_DIR}
	make -C ${USERLAND_TEST}

clean:
	make -C ${KERN_MODULE_DIR} clean
	make -C ${USERLAND_TEST} clean

