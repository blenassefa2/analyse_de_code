#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	void (*buf)(void) = NULL;

	if (argc != 2){
		fprintf(stderr, "Usage: %s <path_to_shellcode>\n", argv[0]);
		return 1;
	}
#if USE_MMAP
	// First option : map a new page as readable/writable/executable
	buf = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE,
                  -1, 0);
	if (buf == MAP_FAILED)
	{
		perror("mmap");
		return 1;
	}
#else
	// Second option : Allocate a normal buffer (read/write)
	// Then call mprotect to make it executable
	buf = malloc(0x1000);
	void *aligned_addr = (void*)((unsigned)buf &~0xfff);
	if(mprotect(aligned_addr, (void*)buf + 0x1000 - aligned_addr, PROT_READ|PROT_WRITE|PROT_EXEC))
	{
		perror("mprotect");
		return 1;
	}
#endif
	int fd = open(argv[1], O_RDONLY);
	if (read(fd, buf, 0x1000)<= 0){
		perror("read");
		return 1;
	}
	buf();
	
	return 0;
}
