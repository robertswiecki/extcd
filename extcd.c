/*
 * ExtCD - A standalone 'cd' command
 * for GNU/Linux (i386)
 *
 * Copyright (C) 2007 Robert Swiecki <robert@swiecki.net>
 * http://www.swiecki.net
 *
 * Licensed under:
 * GNU LESSER GENERAL PUBLIC LICENSE version 2
 * or alternatively under
 * GNU LESSER GENERAL PUBLIC LICENSE version 3
 */


#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <inttypes.h>
#include <sys/reg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <string.h>

static void fatal(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

static void pfatal(const char *msg)
{
	perror(msg);
	exit(1);
}

#define _MAP_START 65536
#define _MAP_SIZE 4096

static void copypath(int ppid, const char *dir)
{
	long *ptr;
	int cnt;

	if ((strlen(dir) + 1) > _MAP_SIZE)
		fatal("directory name too long");

	ptr = (long*) mmap(0, _MAP_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	if (ptr == MAP_FAILED)
		pfatal("mmap");

	strncpy((char*)ptr, dir, _MAP_SIZE);

	for (cnt = 0; cnt < (_MAP_SIZE / sizeof(long)); cnt++)
		if (ptrace(PTRACE_POKEDATA, ppid, _MAP_START + (cnt * sizeof(long)), ptr[cnt]) == -1)
			pfatal("ptrace");

	munmap((void*)ptr, _MAP_SIZE);
}

static int changepdir(pid_t ppid, int count, const char *dir)
{
	uint32_t eax;

	eax = ptrace(PTRACE_PEEKUSER, ppid, 4 * ORIG_EAX, 0, 0);

	if (eax == __NR_waitpid && count == 0) {
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * ORIG_EAX, __NR_mmap2) == -1)
				pfatal("ptrace");
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * EBX, _MAP_START) == -1)
				pfatal("ptrace");
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * ECX, _MAP_SIZE) == -1)
				pfatal("ptrace");
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * EDX, PROT_READ | PROT_WRITE) == -1)
				pfatal("ptrace");
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * ESI, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE ) == -1)
				pfatal("ptrace");

		return 1;
	}


	if (eax == __NR_mmap2 && count == 1) {
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * EAX, 0) == -1)
				pfatal("ptrace");

		copypath(ppid, dir);

		return 1;
	}

	if (eax == __NR_waitpid && count == 2) {
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * ORIG_EAX, __NR_chdir) == -1)
				pfatal("ptrace");
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * EBX, _MAP_START) == -1)
				pfatal("ptrace");

		return 1;
	}

	if (eax == __NR_chdir && count == 3) {
		if (ptrace(PTRACE_POKEUSER, ppid, 4 * EAX, 0) == -1)
				pfatal("ptrace");

		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int status, count = 0;
	pid_t ppid;

	if (argc != 2)
		fatal("Usage: cd [dir]");

	ppid = getppid();
	if (ptrace(PTRACE_ATTACH, ppid, 0, 0) == -1)
		pfatal("ptrace");

	for (;;) {
		if (wait(&status) != ppid)
			continue;

		if (WIFEXITED(status))
			fatal("Process finished\n");

                if (WIFSIGNALED(status))
                        fatal("Process finished with signal");

		if (!WIFSTOPPED(status))
			continue;

		if (WSTOPSIG(status) == SIGTRAP)
			count += changepdir(ppid, count, argv[1]);

		if (count == 4) {
			ptrace(PTRACE_DETACH, ppid, 0, 0);
			return 0;
		}

		if (ptrace(PTRACE_SYSCALL, ppid, 0, 0) == -1)
			pfatal("ptrace");
	}

	return 0;
}
