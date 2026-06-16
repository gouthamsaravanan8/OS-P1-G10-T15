# Top-Level Makefile — USB File Transfer Activity Driver (Project 15)
#
# This Makefile orchestrates the full build pipeline for the project:
#   1. Compiles the kernel module (usb_audit.ko) in src_kernel/
#   2. Compiles the user-space C application (usb_monitor) in src_user/
#
# Targets:
#   make all        — build everything (default)
#   make kernel     — build only the kernel module
#   make user       — build only the user-space application
#   make clean      — remove all build artifacts
#
# Project:  Group 10 — CSC1107
# Target:   Raspberry Pi 4, Raspbian 64-bit

CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -I./include
USER_SRC = src_user/usb_monitor.c
USER_BIN = src_user/usb_monitor

.PHONY: all kernel user clean

# -------------------------------------------------------------------------
# Default: build everything
# -------------------------------------------------------------------------
all: kernel user

# -------------------------------------------------------------------------
# Kernel module
# -------------------------------------------------------------------------
kernel:
	$(MAKE) -C src_kernel

# -------------------------------------------------------------------------
# User-space application
# -------------------------------------------------------------------------
user: $(USER_BIN)

$(USER_BIN): $(USER_SRC) include/usb_tracker.h
	$(CC) $(CFLAGS) -o $@ $<

# -------------------------------------------------------------------------
# Clean
# -------------------------------------------------------------------------
clean:
	$(MAKE) -C src_kernel clean
	rm -f $(USER_BIN)
