/*
 * GLOBAL.cpp
 *
 *  Created on: Apr 28, 2020
 *      Author: xd
 */

#include "GLOBAL.h"

void sig_handler(int sig) {
	int retval;
	if (sig == SIGCHLD) {
		// 等待子程序的結束狀態
		int pid = wait(&retval);
		PINFO("Child ended with state: " << retval << ". (pid:" << pid << ")");
	}
}

int forkm() {
	/* 讓父行程不必等待子行程結束 */
	signal(SIGCHLD, sig_handler);
	int ret = fork();
	switch (ret) {
	case -1:
		exit(0);
	case 0:
		return 0;
	default:
		return ret;
	}
}

