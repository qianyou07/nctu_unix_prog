#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>

typedef int (*chmod_type)(const char *path, mode_t mode);
typedef int (*chown_type)(const char *path, uid_t owner, gid_t group);
typedef int (*close_type)(int fildes);
typedef int (*creat_type)(const char *path, mode_t mode);
typedef int (*fclose_type)(FILE *stream);
typedef FILE *(*fopen_type)(const char *pathname,const char *mode);
typedef size_t (*fread_type)(void *ptr, size_t size, size_t nmemb, FILE *stream);
typedef size_t (*fwrite_type)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
typedef int (*open_type)(const char *path, int flags, ...);
typedef ssize_t (*read_type)(int fildes, void *buf, size_t nbyte);
typedef int (*remove_type)(const char *pathname);
typedef int (*rename_type)(const char *old, const char *new);
typedef FILE *(*tmpfile_type)(void);
typedef ssize_t (*write_type)(int fildes, const void *buf, size_t nbyte);



int chmod(const char *path, mode_t mode){
	char resolve_path[512];
	chmod_type origin = (chmod_type)dlsym(RTLD_NEXT,"chmod");
	int ret = origin(path,mode);
	// if(realpath(path,resolve_path) == NULL){
	// 	fprintf(stderr,"%s\n",path);
	// }
	dprintf(16,"[logger] chmod(\"%s\", %o) = %d\n",realpath(path,resolve_path),mode,ret);
	return ret;
}

int chown(const char *path, uid_t owner, gid_t group){
	char resolve_path[512];
	chown_type origin = (chown_type)dlsym(RTLD_NEXT,"chown");
	int ret = origin(path,owner,group);
	// if(realpath(path,resolve_path) == NULL){
	// 	dprintf(16,"%s\n",path);
	// }
	dprintf(16,"[logger] chown(\"%s\", %d, %d) = %d\n",realpath(path,resolve_path),owner,group,ret);
	return ret;
}

int close(int fildes){
	close_type origin = (close_type)dlsym(RTLD_NEXT,"close");
	pid_t pid = getpid();
	char linkpath[1024] = {0};
	char buf[512] = {0},p[10] = {0},f[10] = {0};
	sprintf(p,"%d",pid);
	sprintf(f,"%d",fildes);
	strcpy(linkpath,"/proc/");
	strcat(linkpath,p);
	strcat(linkpath,"/fd/");
	strcat(linkpath,f);
	readlink(linkpath,buf,512);
	int ret = origin(fildes);
	dprintf(16,"[logger] close(\"%s\") = %d\n",buf,ret);
	return ret;
}

int creat(const char *path, mode_t mode){
	char resolve_path[512];
	creat_type origin = (creat_type)dlsym(RTLD_NEXT,"creat");
	int ret = origin(path,mode);
	// if(realpath(path,resolve_path) == NULL){
	// 	dprintf(16,"%s\n",path);
	// }
	dprintf(16,"[logger] creat(\"%s\", %o) = %d\n",realpath(path,resolve_path),mode,ret);
	return ret;
}

int creat64(const char *path, mode_t mode){
	char resolve_path[512];
	creat_type origin = (creat_type)dlsym(RTLD_NEXT,"creat64");
	int ret = origin(path,mode);
	// if(realpath(path,resolve_path) == NULL){
	// 	dprintf(16,"%s\n",path);
	// }
	dprintf(16,"[logger] creat64(\"%s\", %o) = %d\n",realpath(path,resolve_path),mode,ret);
	return ret;
}

int fclose(FILE *stream){
	char f[10] = {0}, p[10] = {0};
	int fd = fileno(stream);
	pid_t pid = getpid();
	char linkpath[1024] = {0};
	char buf[512] = {0};
	sprintf(p,"%d",pid);
	sprintf(f,"%d",fd);
	strcpy(linkpath,"/proc/");
	strcat(linkpath,p);
	strcat(linkpath,"/fd/");
	strcat(linkpath,f);
	readlink(linkpath,buf,512);
	fclose_type origin = (fclose_type)dlsym(RTLD_NEXT,"fclose");
	int ret = origin(stream);
	dprintf(16,"[logger] fclose(\"%s\") = %d\n",buf,ret);
	return ret;
}

FILE *fopen(const char *pathname, const char *mode){
	char resolve_path[512];
	fopen_type origin = (fopen_type)dlsym(RTLD_NEXT,"fopen");
	FILE *ret = origin(pathname,mode);
	// if(realpath(pathname,resolve_path) == NULL){
	// 	dprintf(16,"%s\n",pathname);
	// }
	dprintf(16,"[logger] fopen(\"%s\", \"%s\") = %p\n",realpath(pathname,resolve_path),mode,ret);
	return ret;
}

FILE *fopen64(const char *pathname, const char *mode){
	char resolve_path[512];
	fopen_type origin = (fopen_type)dlsym(RTLD_NEXT,"fopen64");
	FILE *ret = origin(pathname,mode);
	// if(realpath(pathname,resolve_path) == NULL){
	// 	dprintf(16,"%s\n",pathname);
	// }
	dprintf(16,"[logger] fopen64(\"%s\", \"%s\") = %p\n",realpath(pathname,resolve_path),mode,ret);
	return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream){
	char f[10] = {0}, p[10] = {0};
	int fd = fileno(stream);
	pid_t pid = getpid();
	char linkpath[1024] = {0};
	char buf[512] = {0};
	sprintf(p,"%d",pid);
	sprintf(f,"%d",fd);
	strcpy(linkpath,"/proc/");
	strcat(linkpath,p);
	strcat(linkpath,"/fd/");
	strcat(linkpath,f);
	readlink(linkpath,buf,512);
	fread_type origin = (fread_type)dlsym(RTLD_NEXT,"fread");
	size_t ret = origin(ptr,size,nmemb,stream);
	char str[33] = {0};
	for(size_t i = 0;i < ret*size && i < 32;i++){
		char *c = (char *)ptr+i;
		if(!isprint((int)*c)){
			strcat(str,".");
		}
		else{
			strncat(str,c,1);
		}
	}
	dprintf(16,"[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n",str,size,nmemb,buf,ret);
	return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){
	char f[10] = {0}, p[10] = {0};
	int fd = fileno(stream);
	pid_t pid = getpid();
	char linkpath[1024] = {0};
	char buf[512] = {0};
	sprintf(p,"%d",pid);
	sprintf(f,"%d",fd);
	strcpy(linkpath,"/proc/");
	strcat(linkpath,p);
	strcat(linkpath,"/fd/");
	strcat(linkpath,f);
	readlink(linkpath,buf,512);
	fwrite_type origin = (fwrite_type)dlsym(RTLD_NEXT,"fwrite");
	size_t ret = origin(ptr,size,nmemb,stream);
	char str[33] = {0};
	for(size_t i = 0;i < ret*size && i < 32;i++){
		char *c = (char *)ptr+i;
		if(!isprint((int)*c)){
			strcat(str,".");
		}
		else{
			strncat(str,c,1);
		}
	}
	dprintf(16,"[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n",str,size,nmemb,buf,ret);
	return ret;
}

int open(const char *path, int flags, ...){
	va_list args;
	va_start(args,flags);
	mode_t mode = va_arg(args,mode_t);
	va_end(args);
	char resolve_path[512];
	open_type origin = (open_type)dlsym(RTLD_NEXT,"open");
	int ret;
	if(__OPEN_NEEDS_MODE(flags)){
		ret = origin(path,flags,mode);
		dprintf(16,"[logger] open(\"%s\", %o, %o) = %d\n",realpath(path,resolve_path),flags,mode,ret);
	}
	else{
		ret = origin(path,flags);
		dprintf(16,"[logger] open(\"%s\", %o, %o) = %d\n",realpath(path,resolve_path),flags,0,ret);
	}
	return ret;
}

int open64(const char *path, int flags, ...){
	va_list args;
	va_start(args,flags);
	mode_t mode = va_arg(args,mode_t);
	va_end(args);
	char resolve_path[512];
	open_type origin = (open_type)dlsym(RTLD_NEXT,"open64");
	int ret;
	if(__OPEN_NEEDS_MODE(flags)){
		ret = origin(path,flags,mode);
		dprintf(16,"[logger] open64(\"%s\", %o, %o) = %d\n",realpath(path,resolve_path),flags,mode,ret);
	}
	else{
		ret = origin(path,flags);
		dprintf(16,"[logger] open64(\"%s\", %o, %o) = %d\n",realpath(path,resolve_path),flags,0,ret);
	}
	return ret;
}


ssize_t read(int fildes, void *buf, size_t nbyte){
	pid_t pid = getpid();
	char linkpath[1024] = {0};
	char buffer[512] = {0},p[10] = {0},f[10] = {0};
	sprintf(p,"%d",pid);
	sprintf(f,"%d",fildes);
	strcpy(linkpath,"/proc/");
	strcat(linkpath,p);
	strcat(linkpath,"/fd/");
	strcat(linkpath,f);
	readlink(linkpath,buffer,512);
	read_type origin = (read_type)dlsym(RTLD_NEXT,"read");
	ssize_t ret = origin(fildes,buf,nbyte);
	char str[33] = {0};
	for(ssize_t i = 0;i < ret && i < 32;i++){
		char *c = (char *)buf+i;
		if(!isprint((int)*c)){
			strcat(str,".");
		}
		else{
			strncat(str,c,1);
		}
	}
	dprintf(16,"[logger] read(\"%s\", \"%s\", %ld) = %ld\n",buffer,str,nbyte,ret);
	return ret;
}

int remove(const char *pathname){
	char resolve_path[512];
	// if(realpath(pathname,resolve_path) == NULL){
	// 	dprintf(16,"%s\n",pathname);
	// }
	remove_type origin = (remove_type)dlsym(RTLD_NEXT,"remove");
	int ret = origin(pathname);
	dprintf(16,"[logger] remove(\"%s\") = %d\n",resolve_path,ret);
	return ret;
}

int rename(const char *old, const char *new){
	char old_path[512],new_path[512];
	rename_type origin = (rename_type)dlsym(RTLD_NEXT,"rename");
	realpath(old,old_path);
	int ret = origin(old,new);
	realpath(new,new_path);
	dprintf(16,"[logger] rename(\"%s\", \"%s\") = %d\n",old_path,new_path,ret);
	return ret;
}

FILE *tmpfile(void){
	tmpfile_type origin = (tmpfile_type)dlsym(RTLD_NEXT,"tmpfile");
	FILE *ret = origin();
	dprintf(16,"[logger] tmpfile() = \"%p\"\n",ret);
	return ret;
}

FILE *tmpfile64(void){
	tmpfile_type origin = (tmpfile_type)dlsym(RTLD_NEXT,"tmpfile64");
	FILE *ret = origin();
	dprintf(16,"[logger] tmpfile64() = \"%p\"\n",ret);
	return ret;
}

ssize_t write(int fildes, const void *buf, size_t nbyte){
	pid_t pid = getpid();
	char linkpath[1024] = {0};
	char buffer[512] = {0},p[10] = {0},f[10] = {0};
	sprintf(p,"%d",pid);
	sprintf(f,"%d",fildes);
	strcpy(linkpath,"/proc/");
	strcat(linkpath,p);
	strcat(linkpath,"/fd/");
	strcat(linkpath,f);
	readlink(linkpath,buffer,512);
	write_type origin = (write_type)dlsym(RTLD_NEXT,"write");
	ssize_t ret = origin(fildes,buf,nbyte);
	char str[33] = {0};
	for(ssize_t i = 0;i < ret && i < 32;i++){
		char *c = (char *)buf+i;
		if(!isprint((int)*c)){
			strcat(str,".");
		}
		else{
			strncat(str,c,1);
		}
	}
	dprintf(16,"[logger] write(\"%s\", \"%s\", %ld) = %ld\n",buffer,str,nbyte,ret);
	return ret;
}