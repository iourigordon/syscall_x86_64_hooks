#!/usr/bin/bash

32_BIT_ELF_NAME=syscall_userland_32
64_BIT_ELF_NAME=syscall_userland_64

all: ${32_BIT_ELF_NAME} ${64_BIT_ELF_NAME}
	@echo "Done"

${64_BIT_ELF_NAME}:
	gcc syscall_userland.c -o ${64_BIT_ELF_NAME}

${32_BIT_ELF_NAME}:
	gcc syscall_userland.c -m32 -o ${32_BIT_ELF_NAME}

clean:
	@rm -f ${64_BIT_ELF_NAME}
	@rm -f ${32_BIT_ELF_NAME}
