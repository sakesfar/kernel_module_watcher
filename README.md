# Kernel module watcher
Simple Linux kernel module that sets watchpoints to a specified memory address using **_perf_event API_** + steps for Yocto building

## Steps for PC
1. `cd /to/your/projectsFolder`\
2. `git clone https://github.com/sakesfar/kernel_module_watcher`
3. `cd kernel_module_watcher `
4.  `make`
5. `gcc -o getRandomSafeAddress getRandomSafeAddress.c`
6. The generated `getRandomSafeAddress`run in another terminal to get a random memory address. Copy it and **dont' press anything** afterwards.
7. `sudo insmod watchpoint.ko watch_address="your generated memory address [PASTE HERE]"`
8. Open another terminal `(Ctr+Shift+T)`. `sudo dmesg -w `or `sudo dmesg | tail `. Here we will monitor kernel logs. We will see logs generated by our kernel
9. Shift to the terminal where `getRandomSafeAddress` is running. Press any key
10. Observe the log
11. Try changing the address via `echo "new_address" | sudo tee /sys/kernel/watchpoint/watch_address`. Obtain `"new_address"` again from `getRandomSafeAddress`
12. Remove the module
    `sudo rmmod watchpoint`

> [!WARNING]
> I've not been able to run on qemu x86. The above has been tested only on my PC

## Steps for Yocto build
1. `git clone -b kirkstone git://git.yoctoproject.org/poky`
2. `cd poky`
3. `source oe-init-build-env`
4. Create custom layers:\
  `bitbake-layers create-layer ../meta-custom`\
  `bitbake-layers add-layer ../meta-custom`
6. `mkdir -p ../meta-custom/recipes-kernel/watchpoint/files`
7. Copy `watchpoint.c` and `Makefile` into `../files`.     `cp /path/to/watchpoint.c /path/to/Makefile ../meta-custom/recipes-kernel/watchpoint/files/`
8. Add/copy `watchpoint_0.1.bb` to `../meta-custom/recipes-kernel/watchpoint`
9. Delete content of `Makefile` and insert there content from `Makefile_yocto.txt`. We use slightly different _Makefile_ while building for _Yocto_
10. Build only kernel module : `bitbake watchpoint`






