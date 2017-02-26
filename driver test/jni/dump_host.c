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

#define CMD_BASE 0xC0000000
#define DUMP_MEM (CMD_BASE + 1)
#define SET_PID  (CMD_BASE + 2)

struct dump_request{
    pid_t pid;
    unsigned long addr;
    ssize_t count;
    char *buf;
};

char buf[4096];

int main(int argc, char const *argv[]){
	struct dump_request request;
	if(argc < 2){
		printf("Input target pid\n");
		return -1;
	}
	request.pid = atoi(argv[1]);
	request.addr = 0x40000000;
	request.buf = buf;
	request.count = 1000;

	int fd = open("/dev/REHelper", O_RDWR);
	if(fd == -1){
		printf("[*] open error, check USER!");
		return -1;
	}
	ioctl(fd, DUMP_MEM, &request);
	close(fd);

	if(buf[0] == 0xcc){
		printf("Dump ok\n");
	}
	printf("Done !\n");
	return 0;
}