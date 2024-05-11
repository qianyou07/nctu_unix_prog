#include "libmini.h"

long errno;

#define	WRAPPER_RETval(type)	errno = 0; if(ret < 0) { errno = -ret; return -1; } return ((type) ret);
#define	WRAPPER_RETptr(type)	errno = 0; if(ret < 0) { errno = -ret; return NULL; } return ((type) ret);

ssize_t	read(int fd, char *buf, size_t count) {
	long ret = sys_read(fd, buf, count);
	WRAPPER_RETval(ssize_t);
}

ssize_t readline(int fd,char *buf){
	ssize_t len = 0;
	for(;;len++){
		read(fd,&(buf[len]),1);
		if(buf[len]=='\n') break;
	}
	return len+1;
}

ssize_t	write(int fd, const void *buf, size_t count) {
	long ret = sys_write(fd, buf, count);
	WRAPPER_RETval(ssize_t);
}

/* open is implemented in assembly, because of variable length arguments */

int	close(unsigned int fd) {
	long ret = sys_close(fd);
	WRAPPER_RETval(int);
}

void *	mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
	long ret = sys_mmap(addr, len, prot, flags, fd, off);
	WRAPPER_RETptr(void *);
}

int	mprotect(void *addr, size_t len, int prot) {
	long ret = sys_mprotect(addr, len, prot);
	WRAPPER_RETval(int);
}

int	munmap(void *addr, size_t len) {
	long ret = sys_munmap(addr, len);
	WRAPPER_RETval(int);
}

int	pipe(int *filedes) {
	long ret = sys_pipe(filedes);
	WRAPPER_RETval(int);
}

int	dup(int filedes) {
	long ret = sys_dup(filedes);
	WRAPPER_RETval(int);
}

int	dup2(int oldfd, int newfd) {
	long ret = sys_dup2(oldfd, newfd);
	WRAPPER_RETval(int);
}

int	pause() {
	long ret = sys_pause();
	WRAPPER_RETval(int);
}

int	nanosleep(struct timespec *rqtp, struct timespec *rmtp) {
	long ret = sys_nanosleep(rqtp, rmtp);
	WRAPPER_RETval(int);
}

pid_t	fork(void) {
	long ret = sys_fork();
	WRAPPER_RETval(pid_t);
}

void	exit(int error_code) {
	sys_exit(error_code);
	/* never returns? */
}

char *	getcwd(char *buf, size_t size) {
	long ret = sys_getcwd(buf, size);
	WRAPPER_RETptr(char *);
}

int	chdir(const char *pathname) {
	long ret = sys_chdir(pathname);
	WRAPPER_RETval(int);
}

int	rename(const char *oldname, const char *newname) {
	long ret = sys_rename(oldname, newname);
	WRAPPER_RETval(int);
}

int	mkdir(const char *pathname, int mode) {
	long ret = sys_mkdir(pathname, mode);
	WRAPPER_RETval(int);
}

int	rmdir(const char *pathname) {
	long ret = sys_rmdir(pathname);
	WRAPPER_RETval(int);
}

int	creat(const char *pathname, int mode) {
	long ret = sys_creat(pathname, mode);
	WRAPPER_RETval(int);
}

int	link(const char *oldname, const char *newname) {
	long ret = sys_link(oldname, newname);
	WRAPPER_RETval(int);
}

int	unlink(const char *pathname) {
	long ret = sys_unlink(pathname);
	WRAPPER_RETval(int);
}

ssize_t	readlink(const char *path, char *buf, size_t bufsz) {
	long ret = sys_readlink(path, buf, bufsz);
	WRAPPER_RETval(ssize_t);
}

int	chmod(const char *filename, mode_t mode) {
	long ret = sys_chmod(filename, mode);
	WRAPPER_RETval(int);
}

int	chown(const char *filename, uid_t user, gid_t group) {
	long ret = sys_chown(filename, user, group);
	WRAPPER_RETval(int);
}

int	umask(int mask) {
	long ret = sys_umask(mask);
	WRAPPER_RETval(int);
}

int	gettimeofday(struct timeval *tv, struct timezone *tz) {
	long ret = sys_gettimeofday(tv, tz);
	WRAPPER_RETval(int);
}

uid_t	getuid() {
	long ret = sys_getuid();
	WRAPPER_RETval(uid_t);
}

gid_t	getgid() {
	long ret = sys_getgid();
	WRAPPER_RETval(uid_t);
}

int	setuid(uid_t uid) {
	long ret = sys_setuid(uid);
	WRAPPER_RETval(int);
}

int	setgid(gid_t gid) {
	long ret = sys_setgid(gid);
	WRAPPER_RETval(int);
}

uid_t	geteuid() {
	long ret = sys_geteuid();
	WRAPPER_RETval(uid_t);
}

gid_t	getegid() {
	long ret = sys_getegid();
	WRAPPER_RETval(uid_t);
}

void bzero(void *s, size_t size) {
	char *ptr = (char *) s;
	while(size-- > 0) *ptr++ = '\0';
}

size_t strlen(const char *s) {
	size_t count = 0;
	while(*s++) count++;
	return count;
}

#define	PERRMSG_MIN	0
#define	PERRMSG_MAX	34

static const char *errmsg[] = {
	"Success",
	"Operation not permitted",
	"No such file or directory",
	"No such process",
	"Interrupted system call",
	"I/O error",
	"No such device or address",
	"Argument list too long",
	"Exec format error",
	"Bad file number",
	"No child processes",
	"Try again",
	"Out of memory",
	"Permission denied",
	"Bad address",
	"Block device required",
	"Device or resource busy",
	"File exists",
	"Cross-device link",
	"No such device",
	"Not a directory",
	"Is a directory",
	"Invalid argument",
	"File table overflow",
	"Too many open files",
	"Not a typewriter",
	"Text file busy",
	"File too large",
	"No space left on device",
	"Illegal seek",
	"Read-only file system",
	"Too many links",
	"Broken pipe",
	"Math argument out of domain of func",
	"Math result not representable"
};

void perror(const char *prefix) {
	const char *unknown = "Unknown";
	long backup = errno;
	if(prefix) {
		write(2, prefix, strlen(prefix));
		write(2, ": ", 2);
	}
	if(errno < PERRMSG_MIN || errno > PERRMSG_MAX) write(2, unknown, strlen(unknown));
	else write(2, errmsg[backup], strlen(errmsg[backup]));
	write(2, "\n", 1);
	return;
}

#if 0	/* we have an equivalent implementation in assembly */
unsigned int sleep(unsigned int seconds) {
	long ret;
	struct timespec req, rem;
	req.tv_sec = seconds;
	req.tv_nsec = 0;
	ret = sys_nanosleep(&req, &rem);
	if(ret >= 0) return ret;
	if(ret == -EINTR) {
		return rem.tv_sec;
	}
	return 0;
}
#endif

int setjmp(jmp_buf env){
	setjmp_asm(env);
	env->mask = find_sig();
	return 0;
}

void longjmp(jmp_buf env,int val){
	sigprocmask(SIG_SETMASK,&(env->mask),NULL);
	return longjmp_asm(env,val);
}

sighandler_t signal(int signum,sighandler_t func){
	struct sigaction act,oact;
	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if(signum == SIGALRM){
		#ifdef SA_INTERRUPT
			act.sa_flags |= SA_INTERRUPT;
		#endif
	}
	else{
		#ifdef SA_RESTART
			act.sa_flags |= SA_RESTART;
		#endif
	}
	if(sigaction(signum,&act,&oact) < 0) return (SIG_ERR);
	return (oact.sa_handler);
}

int sigaction(int signum,const struct sigaction *act,struct sigaction *oldact){
	struct sigaction n;
	n.sa_handler = act->sa_handler;
	n.sa_mask = act->sa_mask;
	n.sa_flags = act->sa_flags | SA_RESTORER;
	n.sa_restorer = __myrt/* your customized restore routine, e.g., __myrt */;
	long ret = sys_rt_sigaction(signum,(const struct sigaction *)&n,oldact,sizeof(sigset_t));
	WRAPPER_RETval(int);
}

int sigprocmask(int how,const sigset_t *set,sigset_t *oldset){
	long ret = sys_rt_sigprocmask(how,(sigset_t *)set,oldset,sizeof(sigset_t));
	WRAPPER_RETval(int);
}

int sigpending(sigset_t *set){
	long ret = sys_rt_sigpending(set,sizeof(sigset_t));
	WRAPPER_RETval(int);
}

int sigemptyset(sigset_t *set){
	if(set == NULL){
		errno = EINVAL;
		return -1;
	}
	unsigned long mask = 0;
	*set = (*set) & mask;
	return 0;
}

int sigfillset(sigset_t *set){
	if(set == NULL){
		errno = EINVAL;
		return -1;
	}
	unsigned long fill = 0;
	fill = ~(fill);
	*set = (*set) | fill;
	return 0;
}

int sigaddset(sigset_t *set,int signo){
	int sig = signo - 1;
	if(set == NULL || sig < 0 || sig >= 8*sizeof(sigset_t)){
		errno = EINVAL;
		return -1;
	}
	*set = (*set) | (1UL << sig);
	return 0;
}

int sigdelset(sigset_t *set,int signo){
	int sig = signo - 1;
	if(set == NULL || sig < 0 || sig >= 8*sizeof(sigset_t)){
		errno = EINVAL;
		return -1;
	}
	unsigned long mask = ~(1UL << sig);
	*set = (*set) & mask;
	return 0;
}

int sigismember(const sigset_t *set,int signo){
	int sig = signo - 1;
	if(set == NULL || sig < 0 || sig >= 8*sizeof(sigset_t)){
		errno = EINVAL;
		return -1;
	}
	unsigned long test = (1UL << sig);
	if(((*set) & test) == 0UL) return 0;
	else return 1;
}

unsigned int alarm(unsigned int seconds){
	long ret = sys_alarm(seconds);
	WRAPPER_RETval(int);
}

pid_t getpid(void){
	long ret = sys_getpid();
	WRAPPER_RETval(pid_t);
}

sigset_t find_sig(){
	char fname[128] = "/proc/";
	pid_t pid = getpid();
	char tmp[5]={0};
	int l = 0;
	for(;pid!=0;l++){
		tmp[l] = (pid%10) + '0';
		pid /= 10;
	}
	for(int k=0;l>0;l--){
		fname[6+k] = tmp[l-1];
		k++;
	}
	l = strlen(fname);
	fname[l] = '/';
	fname[l+1] = 's';
	fname[l+2] = 't';
	fname[l+3] = 'a';
	fname[l+4] = 't';
	fname[l+5] = 'u';
	fname[l+6] = 's';
	int fd = open(fname,O_RDONLY);
	char line_buf[128]={0},garbage[128]={0};
	for(int i=0;i<38;i++){readline(fd,garbage);}
	while(garbage[0]!='\t'){read(fd,garbage,1);}
	readline(fd,line_buf);
	sigset_t mask = 0;
	for(int i=0;i<16;i++){
		mask = mask << 4;
		mask += line_buf[i] - '0';
	}
	return mask;
}