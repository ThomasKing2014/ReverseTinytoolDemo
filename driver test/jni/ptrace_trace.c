/*
** Author: ThomasKing
** Date: 2015/02/25
*/ 
#include <sys/stat.h>
#include <unistd.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm/ptrace.h>
#include <sys/inotify.h>

int check_status(){
	int debugged = 0;
	int fp = fopen("/proc/self/status", "r");
	if(fp){
		// ...
		fclose(fp);
	}
	return debugged;
}

int add_notity(){
	int fd_notity = inotify_init();
	if(fd_notity > 0){
		inotify_add_watch(fd_notity, "/proc/self/mem", IN_OPEN | IN_ACCESS | IN_MODIFY);
		//...
	}
	return 0;
}

int main(int argc, char **argv){
	struct pt_regs regs;
	memset(&regs, 0, sizeof(struct pt_regs));

	check_status();
	add_notity();

	pid_t pid = fork();
	if(pid == 0){
		void *base = mmap((void*)0x40000000, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
		if(base == (void*)-1){
			perror("mmap");
		}
		memset(base, 0xaa, 0x1000);
		*(unsigned long*)(base + 4) = 0xbbbbbbbb;
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
			perror("ptrace_traceme");
		}
		kill(getpid(), 19);
		exit(0);
	}else if(pid > 0){
		sleep(1);
		printf("pid: %d, child_pid: %d\n", getpid(), pid);

		if(ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0 ){
			perror( "ptrace_syscall" );
			return -1;
		}
		waitpid(pid, NULL, WUNTRACED );

		if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL ) < 0) {
			perror("ptrace_syscall");
			return -1;
		}
		waitpid(pid, NULL, WUNTRACED);

		unsigned long data = ptrace(PTRACE_PEEKDATA, pid, 0x40000000, 0);
		printf("data: 0x%lx\n", data);
		if(data != 0xaaaaaaaa){
			printf("modify from kernel, data: %lx\n", data);
		}
		kill(pid, 9);
		waitpid(pid, NULL, 0);
	}else{
		printf("fork error\n");
	}
	return 0;
}