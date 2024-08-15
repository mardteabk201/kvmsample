#define _GNU_SOURCE
#include <asm/bootparam.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>


static void guest_init_regs(int vcpu_fd)
{
	struct kvm_regs regs = {};
	struct kvm_sregs sregs = {};

	ioctl(vcpu_fd, KVM_GET_SREGS, &(sregs));
	ioctl(vcpu_fd, KVM_GET_REGS, &(regs));

	sregs.cs.base = 0;
	sregs.cs.limit = ~0;
	sregs.cs.g = 1;
	sregs.ds.base = 0;
	sregs.ds.limit = ~0;
	sregs.ds.g = 1;
	sregs.fs.base = 0;
	sregs.fs.limit = ~0;
	sregs.fs.g = 1;
	sregs.gs.base = 0;
	sregs.gs.limit = ~0;
	sregs.gs.g = 1;
	sregs.es.base = 0;
	sregs.es.limit = ~0;
	sregs.es.g = 1;
	sregs.ss.base = 0;
	sregs.ss.limit = ~0;
	sregs.ss.g = 1;
	sregs.cs.db = 1;
	sregs.ss.db = 1;
	sregs.cr0 |= 1; /* enable protected mode */

	ioctl(vcpu_fd, KVM_SET_SREGS, &sregs);

	regs.rflags = 2;
	regs.rip = 0x100000;
	regs.rsi = 0x10000;

	ioctl(vcpu_fd, KVM_SET_REGS, &(regs));
}

static void guest_init_cpu_id(int kvm_fd, int vcpu_fd)
{
	struct {
		uint32_t nent;
		uint32_t padding;
		struct kvm_cpuid_entry2 entries[100];
	} kvm_cpuid;

	kvm_cpuid.nent = sizeof(kvm_cpuid.entries) / sizeof(kvm_cpuid.entries[0]);
	ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid);

	for (unsigned int i = 0; i < kvm_cpuid.nent; i++) {
		struct kvm_cpuid_entry2 *entry = &kvm_cpuid.entries[i];
		if (entry->function == KVM_CPUID_SIGNATURE) {
			entry->eax = KVM_CPUID_FEATURES;
			entry->ebx = 0x4b4d564b; // KVMK
			entry->ecx = 0x564b4d56; // VMKV
			entry->edx = 0x4d;       // M
		}
	}
	ioctl(vcpu_fd, KVM_SET_CPUID2, &kvm_cpuid);
}

static void guest_load(void *mem, const char *image_path)
{
	size_t datasz;
	void *data;
	int fd = open(image_path, O_RDONLY);
	struct stat st;
	fstat(fd, &st);
	data = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	datasz = st.st_size;
	close(fd);

	struct boot_params *boot =
	    (struct boot_params *)(((uint8_t *)mem) + 0x10000);
	void *cmdline = (void *)(((uint8_t *)mem) + 0x20000);
	void *kernel = (void *)(((uint8_t *)mem) + 0x100000);

	memset(boot, 0, sizeof(struct boot_params));
	memmove(boot, data, sizeof(struct boot_params));
	size_t setup_sectors = boot->hdr.setup_sects;
	size_t setupsz = (setup_sectors + 1) * 512;
	boot->hdr.vid_mode = 0xFFFF; // VGA
	boot->hdr.type_of_loader = 0xFF;
	boot->hdr.ramdisk_image = 0x0;
	boot->hdr.ramdisk_size = 0x0;
	boot->hdr.loadflags |= CAN_USE_HEAP | 0x01 | KEEP_SEGMENTS;
	boot->hdr.heap_end_ptr = 0xFE00;
	boot->hdr.ext_loader_ver = 0x0;
	boot->hdr.cmd_line_ptr = 0x20000;
	memset(cmdline, 0, boot->hdr.cmdline_size);
	memcpy(cmdline, "console=ttyS0", 14);
	memmove(kernel, (char *)data + setupsz, datasz - setupsz);
}

int main(int argc, char *argv[])
{
	int kvm_fd, vm_fd, vcpu_fd;
	void *mem;

	kvm_fd = open("/dev/kvm", O_RDWR);
	vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);

	ioctl(vm_fd, KVM_SET_TSS_ADDR, 0xffffd000);
	__u64 map_addr = 0xffffc000;
	ioctl(vm_fd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr);
	ioctl(vm_fd, KVM_CREATE_IRQCHIP, 0);
	struct kvm_pit_config pit = { .flags = 0 };
	ioctl(vm_fd, KVM_CREATE_PIT2, &pit);

	mem = mmap(NULL, 1 << 30, PROT_READ | PROT_WRITE,
	              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	struct kvm_userspace_memory_region region = {
		.slot = 0,
		.flags = 0,
		.guest_phys_addr = 0,
		.memory_size = 1 << 30,
		.userspace_addr = (__u64)mem,
	};
	ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
	vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);

	guest_init_regs(vcpu_fd);
	guest_init_cpu_id(kvm_fd, vcpu_fd);

	guest_load(mem, argv[1]);

	int run_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	struct kvm_run *run = mmap(0, run_size, PROT_READ | PROT_WRITE,
					MAP_SHARED, vcpu_fd, 0);
	for (;;) {
		ioctl(vcpu_fd, KVM_RUN, 0);

		switch (run->exit_reason) {
		case KVM_EXIT_IO:
			if (run->io.port == 0x3f8 && run->io.direction == KVM_EXIT_IO_OUT) {
				uint32_t size = run->io.size;
				uint64_t offset = run->io.data_offset;
				printf("%.*s", size * run->io.count, (char *)run + offset);
			} else if (run->io.port == 0x3f8 + 5 &&
			           run->io.direction == KVM_EXIT_IO_IN) {
				char *value = (char *)run + run->io.data_offset;
				*value = 0x20;
			}
			break;
		case KVM_EXIT_SHUTDOWN:
			printf("shutdown\n");
			return 0;
		default:
			printf("reason: %d\n", run->exit_reason);
			break;
		}
	}

	return 0;
}
