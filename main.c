/*
 * KVM API Sample.
 * author: Xu He Jie xuhj@cn.ibm.com
 */
#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <pthread.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>

#define KVM_DEVICE "/dev/kvm"
#define RAM_SIZE 512000000
#define CODE_START 0x1000
#define BINARY_FILE "test.bin"

struct kvm {
	int dev_fd;
	int vm_fd;
	__u64 ram_size;
	__u64 ram_start;
	int kvm_version;
	struct kvm_userspace_memory_region mem;
	struct vcpu *vcpus;
	int vcpu_number;
};

struct vcpu {
	int vcpu_id;
	int vcpu_fd;
	pthread_t vcpu_thread;
	struct kvm_run *kvm_run;
	int kvm_run_mmap_size;
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	void *(*vcpu_thread_func)(void *);
};

void load_binary(struct kvm *kvm)
{
	int fd = open(BINARY_FILE, O_RDONLY);
	int ret = 0;
	char *p = (char *)kvm->ram_start;

	while (1) {
		ret = read(fd, p, 4096);
		if (ret <= 0)
			break;
		printf("read size: %d\n", ret);
		p += ret;
	}
}

void kvm_reset_vcpu(struct vcpu *vcpu)
{
	ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &(vcpu->sregs));

	vcpu->sregs.cs.selector = CODE_START;
	vcpu->sregs.cs.base = CODE_START * 16;
	vcpu->sregs.ss.selector = CODE_START;
	vcpu->sregs.ss.base = CODE_START * 16;
	vcpu->sregs.ds.selector = CODE_START;
	vcpu->sregs.ds.base = CODE_START * 16;
	vcpu->sregs.es.selector = CODE_START;
	vcpu->sregs.es.base = CODE_START * 16;
	vcpu->sregs.fs.selector = CODE_START;
	vcpu->sregs.fs.base = CODE_START * 16;
	vcpu->sregs.gs.selector = CODE_START;

	ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs);

	vcpu->regs.rflags = 0x0000000000000002ULL;
	vcpu->regs.rip = 0;
	vcpu->regs.rsp = 0xffffffff;
	vcpu->regs.rbp = 0;

	ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &(vcpu->regs));
}

void *kvm_cpu_thread(void *data)
{
	struct kvm *kvm = (struct kvm *)data;

	kvm_reset_vcpu(kvm->vcpus);
	while (1) {
		printf("KVM start run\n");
		ioctl(kvm->vcpus->vcpu_fd, KVM_RUN, 0);

		switch (kvm->vcpus->kvm_run->exit_reason) {
		case KVM_EXIT_UNKNOWN:
			printf("KVM_EXIT_UNKNOWN\n");
			break;
		case KVM_EXIT_DEBUG:
			printf("KVM_EXIT_DEBUG\n");
			break;
		case KVM_EXIT_IO:
			printf("KVM_EXIT_IO\n");
			printf("out port: %d, data: %d\n",
				kvm->vcpus->kvm_run->io.port,
				*(int *)((char *)(kvm->vcpus->kvm_run) +
				kvm->vcpus->kvm_run->io.data_offset));
			sleep(1);
			break;
		case KVM_EXIT_MMIO:
			printf("KVM_EXIT_MMIO\n");
			break;
		case KVM_EXIT_INTR:
			printf("KVM_EXIT_INTR\n");
			break;
		case KVM_EXIT_SHUTDOWN:
			printf("KVM_EXIT_SHUTDOWN\n");
			goto exit_kvm;
			break;
		default:
			printf("KVM PANIC\n");
			goto exit_kvm;
		}
	}

exit_kvm:
	return 0;
}

int main(int argc, char **argv)
{
	struct kvm *kvm;
	int i = 0;

	kvm = malloc(sizeof(struct kvm));
	memset(kvm, 0, sizeof(struct kvm));

	kvm->dev_fd = open(KVM_DEVICE, O_RDWR);
	kvm->vm_fd = ioctl(kvm->dev_fd, KVM_CREATE_VM, 0);
	kvm->ram_size = RAM_SIZE;
	kvm->ram_start = (__u64)mmap(NULL, kvm->ram_size, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	kvm->mem.memory_size = kvm->ram_size;
	kvm->mem.userspace_addr = kvm->ram_start;
	ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &(kvm->mem));

	load_binary(kvm);

	// only support one vcpu now
	kvm->vcpu_number = 1;

	kvm->vcpus = malloc(sizeof(struct vcpu));
	kvm->vcpus->vcpu_id = 0;
	kvm->vcpus->vcpu_fd = ioctl(kvm->vm_fd, KVM_CREATE_VCPU, kvm->vcpus->vcpu_id);
	kvm->vcpus->kvm_run_mmap_size = ioctl(kvm->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	kvm->vcpus->kvm_run = mmap(NULL, kvm->vcpus->kvm_run_mmap_size,
			PROT_READ | PROT_WRITE, MAP_SHARED, kvm->vcpus->vcpu_fd, 0);
	kvm->vcpus->vcpu_thread_func = kvm_cpu_thread;

	for (i = 0; i < kvm->vcpu_number; i++) {
		pthread_create(&(kvm->vcpus->vcpu_thread), NULL,
			kvm->vcpus[i].vcpu_thread_func, kvm);
		pthread_join(kvm->vcpus->vcpu_thread, NULL);
	}

	//exit
	munmap((void *)kvm->ram_start, kvm->ram_size);
	munmap(kvm->vcpus->kvm_run, kvm->vcpus->kvm_run_mmap_size);
	close(kvm->vm_fd);
	close(kvm->vcpus->vcpu_fd);
	close(kvm->dev_fd);
	free(kvm);

	return 0;
}
