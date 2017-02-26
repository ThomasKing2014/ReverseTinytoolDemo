/*
** Author: ThomasKing
** Date: 2015/02/25
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

#define LEAK_DEV "REHelper"
#define CMD_BASE 0xC0000000
#define DUMP_MEM (CMD_BASE + 1)
#define SET_PID  (CMD_BASE + 2)
#define MODIFY_M (CMD_BASE + 3)


void set_target(pid_t pid){
	int fd = open("/dev/REHelper", O_RDWR);
	if(fd == -1){
		printf("[*] open error, check USER!");
		return ;
	}
	ioctl(fd, SET_PID, pid);
	close(fd);
}

	static ssize_t mem_rw(struct mm_struct *mm, char __user *buf,
	            size_t count, unsigned long addr, int write)
	{
	    ssize_t copied;
	    char *page;

	    if (!mm)
	        return 0;

	    page = (char *)__get_free_page(GFP_TEMPORARY);
	    if (!page)
	        return -ENOMEM;

	    copied = 0;
	    if (!atomic_inc_not_zero(&mm->mm_users))
	        goto free;

	    while (count > 0) {
	        int this_len = min_t(int, count, PAGE_SIZE);

	        if (write && copy_from_user(page, buf, this_len)) {
	            copied = -EFAULT;
	            break;
	        }

	        this_len = access_remote_vm(mm, addr, page, this_len, write);
	        if (!this_len) {
	            if (!copied)
	                copied = -EIO;
	            break;
	        }

	        if (!write && copy_to_user(buf, page, this_len)) {
	            copied = -EFAULT;
	            break;
	        }

	        buf += this_len;
	        addr += this_len;
	        copied += this_len;
	        count -= this_len;
	    }

	    mmput(mm);
	free:
	    free_page((unsigned long) page);
	    return copied;
	}
	
int main(int argc, char const *argv[]){
	int *flag = (int*)mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

	if(flag == (int*)-1){
		perror("mmap error");
		return -1;
	}
	*flag = 0;
	pid_t pid = fork();	
	if(pid < 0){
		perror("fork error");
		return -1;
	}
	if(pid == 0){
		while(!*flag){
			sleep(1);
		}
		char *cmd[] = {"/data/local/tmp/ptrace_trace", NULL};
		execve(cmd[0], &cmd[0], NULL);
		exit(0);
	}
	set_target(pid);
	*flag = 1;
	waitpid(pid, 0, 0);
	munmap(flag, 0x1000);

	return 0;
}