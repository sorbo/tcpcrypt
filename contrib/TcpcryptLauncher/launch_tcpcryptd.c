#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <strings.h>
#include <err.h>

void setup_ipfw_rules();
void run_tcpcryptd(char *);
void teardown_ipfw_rules();

void setup_ipfw_rules() {
	int s = 0;
	
	printf("Setting up ipfw rules...\n");
	s = s || system("/sbin/ipfw 02 add divert 666 tcp from any to any 80");
	s = s || system("/sbin/ipfw 03 add divert 666 tcp from any 80 to any");
	s = s || system("/sbin/ipfw 04 add divert 666 tcp from any to any 7777 via lo0");
	s = s || system("/sbin/ipfw 05 add divert 666 tcp from any 7777 to any via lo0");
	
	if (s) {
		fprintf(stderr, "error setting up firewall rules\n");
		teardown_ipfw_rules();
		exit(1);
	}
}

void run_tcpcryptd(char *argv0) {
	pid_t pid;
	
	strcpy(rindex(argv0, '/'), "/tcpcryptd");
	
	printf("Starting tcpcryptd...\n");
	
	pid = fork();
	if (pid == -1) {
		err(1, "fork()");
	} else if (pid == 0) {
		if (execve(argv0, NULL, NULL) == -1) {
			err(1, "execve()");
		}
    } else {
		waitpid(pid, NULL, 0);
	}

}

void teardown_ipfw_rules() {
	static int done = 0;
	int s = 0;
	
	if (done++) exit(1); /* only run once */
	
	printf("Restoring ipfw to previous configuration...\n");
	s = system("/sbin/ipfw del 02 03 04 05");
	
	if (s) {
		fprintf(stderr, "error restoring ipfw to previous configuration\n");
		exit(1);
	}
}

int main(int argc, char **argv) {
	seteuid(0); setuid(0);
	
	setup_ipfw_rules();
	
	signal(SIGINT, teardown_ipfw_rules);
	signal(SIGQUIT, teardown_ipfw_rules);
	
	run_tcpcryptd(argv[0]);
	
	//teardown_ipfw_rules();
}