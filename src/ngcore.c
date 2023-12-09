#define _GNU_SOURCE 
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <dirent.h>
#include <syscall.h>
#include <sys/resource.h>

#include "elf_parser.h"

#define MAXLINE 1024
#define MAXPROCESS 1024


int ptrace_setrlimit(pid_t pid, int resource);
void read_rlimit(pid_t pid, unsigned long where, struct rlimit *rlim);
void poke_rlimit(pid_t pid, unsigned long where, struct rlimit *rlim);

int poke_text(pid_t pid, void *where, void *new_text, void *old_text, size_t len)
{
	if (len % sizeof(void *) != 0) {
		printf("invalid len, not a multiple of %zd\n", sizeof(void *));
		return -1;
	}

	unsigned long poke_data;
	for (size_t copied = 0; copied < len; copied += sizeof(poke_data)) {
		memmove(&poke_data, new_text + copied, sizeof(poke_data));

		if (old_text != NULL) {
			errno = 0;
			long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
			if (peek_data == -1 && errno) {
				perror("PTRACE_PEEKTEXT");
				return -1;
			}
			memmove(old_text + copied, &peek_data, sizeof(peek_data));
		}

		if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
			perror("PTRACE_POKETEXT");
			return -1;
		}
	}

	return 0;
}

int do_wait(pid_t pid, const char *name) {
	int status;

	if (waitpid(pid, &status, WSTOPPED) == -1) {
		perror("wait");
		return -1;
	}

	if (WIFSTOPPED(status)) {
		if (WSTOPSIG(status) == SIGTRAP) {
			return 0;
		}
		printf("%s unexpectedly got status %s\n", name, strsignal(status));
		return -1;
	}

	printf("%s got unexpected status %d %s\n", name, status, strsignal(status));
	return -1;
}

int singlestep(pid_t pid) {
	if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
		perror("PTRACE_SINGLESTEP");
		return -1;
	}
	return do_wait(pid, "PTRACE_SINGLESTEP");
}

void check_yama(void) {
	FILE *yama_file = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
	if (yama_file == NULL) {
		return;
	}

	char yama_buf[8];
	memset(yama_buf, 0, sizeof(yama_buf));
	fread(yama_buf, 1, sizeof(yama_buf), yama_file);

	if (strcmp(yama_buf, "0\n") != 0) {
		printf("\nThe likely cause of this failure is that your system has "
				"kernel.yama.ptrace_scope = %s",
				yama_buf);
		printf("If you would like to disable Yama, you can run: "
				"sudo sysctl kernel.yama.ptrace_scope=0\n");
	}

	fclose(yama_file);
}

int read_proc_cwd(pid_t pid, char* path_buff, size_t max_size)
{
	char proc_path[MAXLINE];
	sprintf(proc_path, "/proc/%d/cwd", pid);

	ssize_t len = readlink(proc_path, path_buff, max_size - 1);
	if (len == -1){
		return -1;
	}
	path_buff[len] = '\0';

	return 0;
}

int dump_core(pid_t pid) {
	// STEP0 get all threads
	char proc_dir[MAXLINE];
	sprintf(proc_dir, "/proc/%d/task", pid);
	DIR *pDir = opendir(proc_dir);
	if(!pDir){
		return -1;
	}

	struct dirent *pDirent;
	int t_cnt = 0;
	pid_t tids[MAXPROCESS];

	while((pDirent=readdir(pDir)) != NULL){
		if(strcmp(pDirent ->d_name, ".") == 0){
			continue;
		}
		if(strcmp(pDirent ->d_name, "..") == 0){
			continue;
		}
		tids[t_cnt++] = atoi(pDirent ->d_name);
	}

	// STEP1 attach all threads
	for(int i = 0; i < t_cnt; i++){
		if (ptrace(PTRACE_ATTACH, tids[i], NULL, NULL)) {
			check_yama();
			return -1;
		}

		// wait for the process to actually stop
		if (waitpid(tids[i], 0, WSTOPPED) == -1) {
			return -1;
		}
	}

	// save the register state of the remote process
	struct user_regs_struct alloldregs[MAXPROCESS];
	struct user_regs_struct oldregs;

	for(int i = 0; i < t_cnt; i++){
		if (ptrace(PTRACE_GETREGS, tids[i], NULL, &alloldregs[i])) {
			perror("PTRACE_GETREGS");
			ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
			return -1;
		}

		if(tids[i] == pid){
			oldregs = alloldregs[i];
		}
	}

	void *rip = (void *)oldregs.rip;

	struct user_regs_struct newregs;
	memmove(&newregs, &oldregs, sizeof(newregs));

	newregs.rax = 56;	// clone
	newregs.rdi = CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD|CLONE_PTRACE;	// clone flags
	newregs.rsi = 0;	// fn
	newregs.rdx = 0;	// stack
	newregs.r10 = 0;	// flags

	uint8_t old_word[8];
	uint8_t new_word[8];
	new_word[0] = 0x0f;	// SYSCALL
	new_word[1] = 0x05;	// SYSCALL

	// we need to fill a few more bytes with valid instruction to protect target process 
	// from cpu pipeline
	new_word[2] = 0x90;	// NOP
	new_word[3] = 0x90;	// NOP
	new_word[4] = 0x90;	// NOP
	new_word[5] = 0x90;	// NOP
	new_word[6] = 0x90;	// NOP
	new_word[7] = 0x90;	// NOP

	// STEP2 clone target process
	if (poke_text(pid, rip, new_word, old_word, sizeof(new_word))) {
		goto fail;
	}

	// set the new registers with our syscall arguments
	if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
		perror("PTRACE_SETREGS");
		goto fail;
	}

	// invoke clone()
	if (singlestep(pid)) {
		goto fail;
	}

	// get child pid
	if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
		perror("PTRACE_GETREGS");
		return -1;
	}

	pid_t puppet_pid = newregs.rax;
	printf("forked pid : %d\n", puppet_pid);

	// STEP2 restore and detach target process
	poke_text(pid, rip, old_word, NULL, sizeof(old_word));

	printf("restoring registers\n");
	if (ptrace(PTRACE_SETREGS, pid, NULL, &oldregs)) {
		perror("PTRACE_SETREGS");
		goto fail;
	}

	printf("detaching\n");
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH OLD");
		goto fail;
	}

	// STEP3 use kill -SIGSEGV to create a core file in child process
	if (waitpid(puppet_pid, 0, WSTOPPED) == -1) {
		perror("wait");
		return -1;
	}

	// restore child process
	poke_text(puppet_pid, rip, old_word, NULL, sizeof(old_word));
	printf("restoring child old registers\n");
	if (ptrace(PTRACE_SETREGS, puppet_pid, NULL, &oldregs)) {
		perror("PTRACE_SETREGS");
		goto fail;
	}

	// ptrace_setrlimit unlimied
	if(ptrace_setrlimit(puppet_pid, RLIMIT_CORE)){
		return -1;
	}

	poke_text(puppet_pid, rip, old_word, NULL, sizeof(old_word));
	printf("restoring child old registers\n");
	if (ptrace(PTRACE_SETREGS, puppet_pid, NULL, &oldregs)) {
		perror("PTRACE_SETREGS");
		goto fail;
	}

	printf("signal abort to process %d !\n", puppet_pid);
	kill(puppet_pid, SIGABRT);

	if(ptrace(PTRACE_DETACH, puppet_pid, NULL, NULL)) {
		perror("PTRACE_DETACH CHILD");
		goto fail;
	}

	//STEP4 modify core file
	char target_working_dir[MAXLINE];
	char ngcore_working_dir[MAXLINE];

	int read_result = read_proc_cwd(pid, target_working_dir, MAXLINE);
	if(read_result < 0){
		return -1;
	}

	char main_thread_core[MAXLINE];
	char process_core[MAXLINE];
	char pid_str[MAXLINE];
	sprintf(pid_str, "%d", puppet_pid);

	while(!main_thread_core[0]){
		// FIXME timeout
		pDir = opendir(target_working_dir);
		if(!pDir){
			return -1;
		}

		while((pDirent=readdir(pDir)) != NULL){
			if(strstr(pDirent ->d_name, pid_str) != NULL){
				snprintf(main_thread_core, MAXLINE, "%s/%s", target_working_dir, pDirent ->d_name);
				printf("core file found: %s\n", main_thread_core);
				break;
			}
		}

		closedir(pDir);
		sleep(1);
	}

	read_result = read_proc_cwd(getpid(), ngcore_working_dir, MAXLINE);
	if(read_result < 0){
		return -1;
	}

	snprintf(process_core, MAXLINE, "%s/core.%d", ngcore_working_dir, pid);
	if(add_pr_note(main_thread_core, process_core, t_cnt, tids, alloldregs)){
		printf("add pr_note failed\n");
	}

	return 0;

fail:
	poke_text(pid, rip, old_word, NULL, sizeof(old_word));
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		perror("PTRACE_DETACH");
	}
	return 1;
}

int main(int argc, char **argv)
{
	long pid = -1;
	int c;
	opterr = 0;

	while ((c = getopt(argc, argv, "hp:")) != -1) {
		switch (c) {
			case 'h':
				printf("Usage: %s -p <pid>\n", argv[0]);
				return 0;
				break;
			case 'p':
				pid = strtol(optarg, NULL, 10);
				if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN)) ||
						(errno != 0 && pid == 0)) {
					perror("strtol");
					return 1;
				}
				if (pid < 0) {
					fprintf(stderr, "cannot accept negative pids\n");
					return 1;
				}
				break;
			case '?':
				if (optopt == 'p') {
					fprintf(stderr, "Option -p requires an argument.\n");
				} else if (isprint(optopt)) {
					fprintf(stderr, "Unknown option `-%c`.\n", optopt);
				} else {
					fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
				}
				return 1;
				break;
			default:
				abort();
		}
	}
	if (pid == -1) {
		fprintf(stderr, "must specify a remote process with -p\n");
		return 1;
	}

	dump_core((pid_t)pid);
}

int ptrace_setrlimit(pid_t pid, int resource)
{
	struct user_regs_struct orig;
	if (ptrace(PTRACE_GETREGS, pid, 0, &orig)) {
		perror("ptrace(PTRACE_GETREGS, ...)");
		return 1;
	}

	errno = 0;
	const long orig_word = ptrace(PTRACE_PEEKTEXT, pid, orig.rip, 0);
	if (orig_word == -1 && errno) {
		perror("ptrace(PTRACE_PEEKTEXT, ...)");
		return 1;
	}

	if (ptrace(PTRACE_POKETEXT, pid, orig.rip, 0x050f)) {
		perror("ptrace(PTRACE_POKETEXT, ...)");
		return 1;
	}

	struct user_regs_struct new_regs;
	memcpy(&new_regs, &orig, sizeof(new_regs));

	new_regs.rax = SYS_getrlimit;                         // sys_getrlimit
	new_regs.rdi = resource;                              // resource
	new_regs.rsi = new_regs.rsp - sizeof(struct rlimit);  // rlim

	if (ptrace(PTRACE_SETREGS, pid, 0, &new_regs)) {
		perror("ptrace(PTRACE_SETREGS, ...)");
		return 1;
	}

	if (singlestep(pid)) {
		perror("ptrace(PTRACE_SINGLESTEP, ...)");
		return 1;
	}

	if (ptrace(PTRACE_GETREGS, pid, 0, &new_regs)) {
		perror("ptrace(PTRACE_GETREGS, ...)");
		return 1;
	}

	if (new_regs.rip - 2 != orig.rip) {
		//
	}
	if (new_regs.rax != 0) {
		//
	}

	struct rlimit rlim;
	read_rlimit(pid, new_regs.rsp - sizeof(struct rlimit), &rlim);

	if (rlim.rlim_cur == rlim.rlim_max) {
		//
	} else {
		rlim.rlim_cur = rlim.rlim_max;
		poke_rlimit(pid, orig.rsp - sizeof(struct rlimit), &rlim);

		memcpy(&new_regs, &orig, sizeof(new_regs));
		new_regs.rax = SYS_setrlimit;                         // sys_setrlimit
		new_regs.rdi = resource;                              // resource
		new_regs.rsi = new_regs.rsp - sizeof(struct rlimit);  // rlim

		if (ptrace(PTRACE_SETREGS, pid, 0, &new_regs)) {
			perror("ptrace(PTRACE_SETREGS, ...)");
			return 1;
		}

		if (singlestep(pid)) {
			perror("ptrace(PTRACE_SINGLESTEP, ...)");
			return 1;
		}

		if (ptrace(PTRACE_GETREGS, pid, 0, &new_regs)) {
			perror("ptrace(PTRACE_GETREGS, ...)");
			return 1;
		}

		if (new_regs.rip - 2 != orig.rip) {
			//
		}
		if (new_regs.rax != 0) {
			//
		}
	}

	if (ptrace(PTRACE_POKETEXT, pid, orig.rip, orig_word)) {
		perror("ptrace(PTRACE_POKETEXT...");
		return 1;
	}
	if (ptrace(PTRACE_SETREGS, pid, 0, &orig)) {
		perror("ptrace(PTRACE_SETREGS...");
		return 1;
	}

	return 0;
}

void read_rlimit(pid_t pid, unsigned long where, struct rlimit *rlim)
{
	const size_t sz = sizeof(struct rlimit) / sizeof(long);
	for (size_t i = 0; i < sz; i++) {
		errno = 0;
		long word = ptrace(PTRACE_PEEKTEXT, pid, where + i * sizeof(long), 0);

		if (word == -1 && errno) {
			perror("ptrace(PTRACE_PEEKTEXT, ...)");
			exit(1);
		}
		memcpy((long *)(rlim) + i, &word, sizeof(word));
	}
}

void poke_rlimit(pid_t pid, unsigned long where, struct rlimit *rlim)
{
	const size_t sz = sizeof(struct rlimit) / sizeof(long);
	for (size_t i = 0; i < sz; i++) {
		long word;
		memcpy(&word, (long *)(rlim) + i, sizeof(word));

		if (ptrace(PTRACE_POKETEXT, pid, where + i * sizeof(long), word)) {
			perror("ptrace(PTRACE_POKETEXT...)");
		}
	}
}

