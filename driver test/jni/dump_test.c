/*
** Author: ThomasKing
** Date: 2015/02/23
*/ 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>

int main(int argc, char const *argv[]){
	printf("dump_test pid[%d]\n", getpid());
	void *base = mmap((void*)0x40000000, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if(base == (void*)-1){
		printf("mmap error\n");
		return -1;
	}
	memset(base, 0xcc, 0x1000);
	getchar();
	return 0;
}