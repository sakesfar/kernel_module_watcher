DESCRIPTION = "Simple hardware watchpoint kernel module"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://watchpoint.c;beginline=1;endline=10;md5=bb54d53cd5901151bab257d0524b2d0c"

SRC_URI = "file://watchpoint.c \
           file://Makefile"

S = "${WORKDIR}"

inherit module

KERNEL_MODULE_PACKAGE_SUFFIX = "-watchpoint"

DEPENDS += "virtual/kernel"
RPROVIDES_${PN} += "kernel-module-watchpoint"
KERNEL_MODULE_AUTOLOAD += "watchpoint"
KERNEL_MODULE_PROBECONF += "watchpoint"
FILES_${PN} += "${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/watchpoint.ko"
