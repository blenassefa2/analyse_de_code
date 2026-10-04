#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <sys/socket.h>

/*
 * Goal : force the program to execute a reverse shell
*/

char username[256] = {0};

int handle_ping(int cli){
	unsigned short size;
	char buf[1024];

	if (sizeof(size) != read(cli, &size, sizeof(size))){
		fprintf(stderr, "Unable to read size");
		return 1;
	}
	if (size != read(cli, buf, size)){
		fprintf(stderr, "Unable to read data\n");
		return 1;
	}
	write(cli, buf, size);
	return 0;
}

int handle_hello(int cli){
	char buf[1024];
	if (read(cli, username, sizeof(username)) <= 0){
		return 1;
	}
	snprintf(buf, sizeof(buf), "Hello %s", username);
	write(cli, buf, strlen(buf));
	return 0;
}

int handle_bye(int cli){
	char buf[1024];
	snprintf(buf, sizeof(buf), "Bye %s", username);
	write(cli, buf, strlen(buf));
	return 1;
}

int handle_client(int cli){
	unsigned short cmd;
	int stop = 0;

	memset(username, 0, sizeof(username));

	while(!stop){
		if (sizeof(cmd) != read(cli, &cmd, sizeof(cmd))){
			fprintf(stderr, "Unable to read command");
			return 1;
		}
		switch(cmd){
		case 0:
			stop = handle_hello(cli);
			break;
		case 1:
			stop = handle_ping(cli);
			break;
		case 2:
			stop = handle_bye(cli);
			break;
		}
	}
	return 0;
}

int main(int argc, char **argv){
	int sock, cli;
	struct sockaddr_in saddr = {0};
	int one = 1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1){
		perror("socket");
		return 1;
	}
	if (-1 == setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one))){
		perror("setsockopt");
		return 1;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(55555);
	saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (-1 == bind(sock, (struct sockaddr*)&saddr, sizeof(saddr))){
		perror("bind");
		return 1;
	}
	if (-1 == listen(sock, 10)){
		perror("listen");
		return 1;
	}
	while(1){
		cli = accept(sock, NULL, 0);
		if (cli < 0){
			perror("accept");
			return 1;
		}
		if (0 == fork()){
			close(sock);
			return handle_client(cli);
		}else{
			close(cli);
		}
	}
	
	return 0;
}
