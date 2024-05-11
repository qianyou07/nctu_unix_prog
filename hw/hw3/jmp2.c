#include "libmini.h"

typedef void (*proc_t)();
static jmp_buf jb;

int main() {
	int aut=0;
	register int regi=1;
	volatile int vol=2;
	static int sta=3;
	sigset_t s;
	sigemptyset(&s);
	sigaddset(&s, SIGALRM);
	sigaddset(&s, SIGQUIT);
	sigprocmask(SIG_BLOCK, &s, NULL);
	find_sig();
	if(setjmp(jb) != 0) {
		write(1,"after longjmp:\n",15);
		find_sig();
		// if(aut==0) write(1,"auto=0\n",7);
		// else if(aut==4) write(1,"auto=4\n",7);
		// if(regi==1) write(1,"reg=1\n",6);
		// else if(regi==5) write(1,"reg=5\n",6);
		// if(vol==2) write(1,"volatile=2\n",11);
		// else if(vol==6) write(1,"volatile=6\n",11);
		// if(sta==3) write(1,"static=3\n",9);
		// else if(sta==7) write(1,"static=7\n",9);
	}
	else{
		sigfillset(&s);
		sigprocmask(SIG_BLOCK, &s, NULL);
		find_sig();
		aut=4;
		regi=5;
		vol=6;
		sta=7;
		longjmp(jb,1);
	}
	return 0;
}

