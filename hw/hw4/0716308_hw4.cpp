#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include "0716308_hw4.h"
#include <string>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <capstone/capstone.h>
#include <list>

using namespace std;

#define	PEEKSIZE 8

int state = 0; // 0:not loaded 1:loaded 2:running
pid_t child;
char f_path[128] = {0};
list<unsigned long long> break_list;
static csh cshandle = 0;
static map<long long, instruction1> instructions;
static map<range_t, map_entry_t> vmmap;
range_t text;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

void err(const char *msg){
	printf("%s\n",msg);
	exit(-1);
}

bool find(unsigned long long addr){
	for(list<unsigned long long>::iterator it = break_list.begin();it != break_list.end();it++){
		if(*it == addr) return true;
	}
	return false;
}

bool in_text(unsigned long long addr){
	return (addr >= text.begin && addr <text.end);
}

bool operator<(range_t r1, range_t r2) {
	if(r1.begin < r2.begin && r1.end < r2.end) return true;
	return false;
}

int load_maps(map<range_t, map_entry_t>& loaded) {
	char fn[128];
	char buf[256];
	FILE *fp;
	snprintf(fn, sizeof(fn), "/proc/%u/maps", child);
	if((fp = fopen(fn, "rt")) == NULL) return -1;
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		int nargs = 0;
		char *token, *saveptr, *args[8], *ptr = buf;
		map_entry_t m;
		while(nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL) {
			args[nargs++] = token;
			ptr = NULL;
		}
		if(nargs < 6) continue;
		if((ptr = strchr(args[0], '-')) != NULL) {
			*ptr = '\0';
			m.range.begin = strtol(args[0], NULL, 16);
			m.range.end = strtol(ptr+1, NULL, 16);
		}
		m.inode = strtoul(args[4],NULL,10);
		m.name = args[5];
		m.perm = 0;
		m.perm_str = "";
		if(args[1][0] == 'r'){
			m.perm |= 0x04;
			m.perm_str += "r";
		}
		else{
			m.perm_str += "-";
		}
		if(args[1][1] == 'w'){
			m.perm |= 0x02;
			m.perm_str += "w";
		}
		else{
			m.perm_str += "-";
		}
		if(args[1][2] == 'x'){
			m.perm |= 0x01;
			m.perm_str += "x";
		}
		else{
			m.perm_str += "-";
		}
		m.offset = strtol(args[2], NULL, 16);
		loaded[m.range] = m;
	}
	return (int) loaded.size();
}

instruction1 *search(unsigned long long addr){
	int count;
	char buf[64] = { 0 };
	unsigned long long ptr = addr;
	cs_insn *insn;
	map<long long, instruction1>::iterator mi; // from memory addr to instruction

	if((mi = instructions.find(addr)) != instructions.end()) {
		return &(mi->second);
	}

	for(ptr = addr; ptr < addr + sizeof(buf); ptr += PEEKSIZE) {
		long long peek;
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT, child, ptr, NULL);
		if(errno != 0) break;
		memcpy(&buf[ptr-addr], &peek, PEEKSIZE);
	}

	if(ptr == addr)  {
		errquit("search");
	}

	if((count = cs_disasm(cshandle, (uint8_t*) buf, addr-ptr, addr, 0, &insn)) > 0) {
		int i;
		for(i = 0; i < count; i++) {
			instruction1 in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
		}
		cs_free(insn, count);
	}

	if((mi = instructions.find(addr)) != instructions.end()) {
		return &(mi->second);
	} else {
		errquit("search");
	}
	return NULL;
}

void disassemble(unsigned long long addr,unsigned instr_count,bool check) {
	int count;
	char buf[64] = { 0 };
	unsigned long long ptr;
	cs_insn *insn;
	map<long long, instruction1>::iterator mi; // from memory addr to instruction
	for(unsigned i = 0;i < instr_count;i++){
		if(check && (!in_text(addr))) break;
		memset(buf,0,64);
		ptr = addr;
		if((mi = instructions.find(addr)) != instructions.end()) {
			print_instruction(addr, &mi->second);
			addr += mi->second.size;
			continue;
		}

		for(ptr = addr; ptr < addr + sizeof(buf); ptr += PEEKSIZE) {
			long long peek;
			errno = 0;
			peek = ptrace(PTRACE_PEEKTEXT, child, ptr, NULL);
			if(errno != 0) break;
			memcpy(&buf[ptr-addr], &peek, PEEKSIZE);
		}

		if(ptr == addr)  {
			print_instruction(addr, NULL);
			return;
		}

		if((count = cs_disasm(cshandle, (uint8_t*) buf, addr-ptr, addr, 0, &insn)) > 0) {
			int i;
			for(i = 0; i < count; i++) {
				instruction1 in;
				in.size = insn[i].size;
				in.opr  = insn[i].mnemonic;
				in.opnd = insn[i].op_str;
				memcpy(in.bytes, insn[i].bytes, insn[i].size);
				instructions[insn[i].address] = in;
			}
			cs_free(insn, count);
		}

		if((mi = instructions.find(addr)) != instructions.end()) {
			print_instruction(addr, &mi->second);
			addr += mi->second.size;
			continue;
		} else {
			print_instruction(addr, NULL);
		}
	}

	return;
}

void print_instruction(long long addr, instruction1 *in) {
	int i;
	char bytes[128] = "";
	if(in == NULL) {
		fprintf(stdout, "\t%llx:\t<cannot disassemble>\n", addr);
	} else {
		for(i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		fprintf(stdout, "\t%llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
	}
}

void load(char *path){
	if(state != 0) err("** Program is already loaded");
	memset(f_path,0,128);
	strcpy(f_path,path);
	if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK){
		errquit("cs_open");
	}
	FILE *load_file;
	Elf64_Ehdr elf_header;
	Elf64_Shdr sheader;
	if((load_file = fopen64(path,"rb")) == NULL){
		errquit("Load");
	}
	fread(&elf_header,1,sizeof(elf_header),load_file);
	text.begin = elf_header.e_entry;
	fseek(load_file,elf_header.e_shoff,SEEK_SET);
	for(int i = 0;i < elf_header.e_shnum;i++){
		fread(&sheader,1,sizeof(sheader),load_file);
		if(sheader.sh_type == SHT_PROGBITS && sheader.sh_addr == text.begin){
			text.end = text.begin + sheader.sh_size;
			break;
		}
	}
	fclose(load_file);
	state = 1;
	printf("** program '%s' loaded. entry point 0x%lx\n",path,elf_header.e_entry);
}

void start(){
	if(state == 0) err("** Program is not loaded");
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
		execlp(f_path, f_path, NULL);
		errquit("execlp");
	} else {
		printf("** pid %d\n",child);
		int status;
		if(waitpid(child, &status, 0) < 0) errquit("waitpid");
		assert(WIFSTOPPED(status));
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
		state = 2;
	}
}

void run(){
	if(state == 2){
		printf("** program %s is already running.\n",f_path);
		cont();
	}
	else if(state == 1){
		if((child = fork()) < 0) errquit("fork");
		if(child == 0) {
			if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
			execlp(f_path, f_path, NULL);
			errquit("execlp");
		} else {
			printf("** pid %d\n",child);
			int status;
			if(waitpid(child, &status, 0) < 0) errquit("waitpid");
			assert(WIFSTOPPED(status));
			ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
			ptrace(PTRACE_CONT, child, 0, 0);
			while(waitpid(child, &status, 0) > 0) {
				if(WIFEXITED(status) || WIFSIGNALED(status)){
					printf("** child process %d terminiated normally (code %d)\n",child,WEXITSTATUS(status));
					break_list.clear();
					state = 1;
					break;
				}
				else if(WIFSTOPPED(status)){
					struct user_regs_struct regs;
					unsigned long long rip;
					rip = ptrace(PTRACE_PEEKUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),0);
					if(find(rip-1)){
						instruction1 *inst = search(rip-1);
						unsigned long long code = 0;
						unsigned long long origin = ptrace(PTRACE_PEEKTEXT,child,rip-1,NULL);
						int size = (inst->size > PEEKSIZE)? PEEKSIZE:inst->size;
						memcpy(&code,inst->bytes,size);
						memcpy((unsigned char *)&code+size,(unsigned char *)&origin+size,PEEKSIZE-size);
						ptrace(PTRACE_POKETEXT,child,rip-1,code);
						ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),rip-1);
						printf("** breakpoint @");
						disassemble(rip-1,1,false);
					}
					break;
				};
			}
		}
	}
	else err("** Program is not loaded");
}

void cont(){
	if(state != 2) err("** Process is not running");
	struct user_regs_struct regs;
	unsigned long long rip,code;
	int status;
	rip = ptrace(PTRACE_PEEKUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),0);
	code = ptrace(PTRACE_PEEKTEXT,child,rip,NULL) & 0xff;
	if(find(rip) && code != 0xcc){
		ptrace(PTRACE_SINGLESTEP,child,0,0);
		if(waitpid(child, &status, 0) < 0) errquit("waitpid");
		if(WIFEXITED(status) || WIFSIGNALED(status)){
			printf("** child process %d terminiated normally (code %d)\n",child,WEXITSTATUS(status));
			break_list.clear();
			state = 1;
			return;
		}
		else if(WIFSTOPPED(status)){
			instruction1 *inst = search(rip);
			code = 0;
			unsigned long long origin = ptrace(PTRACE_PEEKTEXT,child,rip,NULL);
			int size = (inst->size > PEEKSIZE)? PEEKSIZE:inst->size;
			memcpy(&code,inst->bytes,size);
			memcpy((unsigned char *)&code+size,(unsigned char *)&origin+size,PEEKSIZE-size);
			code = (code & 0xffffffffffffff00) | 0xcc;
			ptrace(PTRACE_POKETEXT,child,rip,code);
		}
	}
	ptrace(PTRACE_CONT, child, 0, 0);
	while(waitpid(child, &status, 0) > 0) {
		if(WIFEXITED(status) || WIFSIGNALED(status)){
			printf("** child process %d terminiated normally (code %d)\n",child,WEXITSTATUS(status));
			break_list.clear();
			state = 1;
			break;
		}
		else if(WIFSTOPPED(status)){
			rip = ptrace(PTRACE_PEEKUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),0);
			if(find(rip-1)){
				instruction1 *inst = search(rip-1);
				code = 0;
				unsigned long long origin = ptrace(PTRACE_PEEKTEXT,child,rip-1,NULL);
				int size = (inst->size > PEEKSIZE)? PEEKSIZE:inst->size;
				memcpy(&code,inst->bytes,size);
				memcpy((unsigned char *)&code+size,(unsigned char *)&origin+size,PEEKSIZE-size);
				ptrace(PTRACE_POKETEXT,child,rip-1,code);
				ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),rip-1);
				printf("** breakpoint @\t");
				disassemble(rip-1,1,false);
			}
			break;
		};
	}
}

void set_breakpoint(char *addr){
	if(state != 2){
		printf("** cannot set breakpoint while the program is not running\n");
		return;
	}
	unsigned long long address = strtoull(addr,NULL,16);
	break_list.push_back(address);
	instruction1 *inst = search(address);
	unsigned long long code = 0;
	unsigned long long origin = ptrace(PTRACE_PEEKTEXT,child,address,NULL);
	int size = (inst->size > PEEKSIZE)? PEEKSIZE:inst->size;
	memcpy(&code,inst->bytes,size);
	memcpy((unsigned char *)&code+size,(unsigned char *)&origin+size,PEEKSIZE-size);
	code = (code & 0xffffffffffffff00) | 0xcc;
	ptrace(PTRACE_POKETEXT,child,address,code);
}

void delete_breakpoint(char *id){
	unsigned long i = strtoul(id,NULL,10);
	if(state != 2 || i >= break_list.size()) err("** Process is not running or break point id is not in the list");
	printf("** breakpoint %ld deleted.\n",i);
	unsigned long long address;
	for(list<unsigned long long>::iterator it = break_list.begin();it != break_list.end();it++){
		if(i-- == 0){
			address = *it;
			break_list.erase(it);
			break;
		}
	}
	instruction1 *inst = search(address);
	unsigned long long code = 0;
	unsigned long long origin = ptrace(PTRACE_PEEKTEXT,child,address,NULL);
	int size = (inst->size > PEEKSIZE)? PEEKSIZE:inst->size;
	memcpy(&code,inst->bytes,size);
	memcpy((unsigned char *)&code+size,(unsigned char *)&origin+size,PEEKSIZE-size);
	ptrace(PTRACE_POKETEXT,child,address,code);
}

void list_breakpoint(){
	if(break_list.size() == 0){
		printf("** There is no break point\n");
		return;
	}
	int i = 0;
	printf("** ");
	for(auto b:break_list){
		printf("%d:  %llx  ",i,b);
		i++;
	}
	printf("\n");
}
void get(char *reg){
	if(state != 2) err("** Process is not running");
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS,child,0,&regs) != 0) errquit("getregs");
	if(strcmp(reg,"rax") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rax,regs.rax);
	}
	if(strcmp(reg,"rbx") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rbx,regs.rbx);
	}
	if(strcmp(reg,"rcx") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rcx,regs.rcx);
	}
	if(strcmp(reg,"rdx") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rdx,regs.rdx);
	}
	if(strcmp(reg,"r8") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.r8,regs.r8);
	}
	if(strcmp(reg,"r9") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.r9,regs.r9);
	}
	if(strcmp(reg,"r10") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.r10,regs.r10);
	}
	if(strcmp(reg,"r11") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.r11,regs.r11);
	}
	if(strcmp(reg,"r12") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.r12,regs.r12);
	}
	if(strcmp(reg,"r13") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.r13,regs.r13);
	}
	if(strcmp(reg,"r14") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.r14,regs.r14);
	}
	if(strcmp(reg,"r15") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.r15,regs.r15);
	}
	if(strcmp(reg,"rdi") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rdi,regs.rdi);
	}
	if(strcmp(reg,"rsi") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rsi,regs.rsi);
	}
	if(strcmp(reg,"rbp") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rbp,regs.rbp);
	}
	if(strcmp(reg,"rsp") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rsp,regs.rsp);
	}
	if(strcmp(reg,"rip") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.rip,regs.rip);
	}
	if(strcmp(reg,"flags") == 0){
		printf("%s = %llu (0x%llx)\n",reg,regs.eflags,regs.eflags);
	}
}

void getregs(){
	if(state != 2) err("** Process is not running");
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS,child,0,&regs) != 0) errquit("getregs");
	printf("RAX %-18llxRBX %-18llxRCX %-18llxRDX %-18llx\n",regs.rax,regs.rbx,regs.rcx,regs.rdx);
	printf("R8  %-18llxR9  %-18llxR10 %-18llxR11 %-18llx\n",regs.r8,regs.r9,regs.r10,regs.r11);
	printf("R12 %-18llxR13 %-18llxR14 %-18llxR15 %-18llx\n",regs.r12,regs.r13,regs.r14,regs.r15);
	printf("RDI %-18llxRSI %-18llxRBP %-18llxRSP %-18llx\n",regs.rdi,regs.rsi,regs.rbp,regs.rsp);
	printf("RIP %-18llxFLAGS %016llx\n",regs.rip,regs.eflags);
}

void print_map(){
	if(state != 2){
		printf("** cannot print vmmap while the program is not running\n");
		return;
	}
	vmmap.clear();
	load_maps(vmmap);
	for(auto mi:vmmap){
		printf("%016lx-%016lx %s %lu\t%s\n",mi.second.range.begin,mi.second.range.end,mi.second.perm_str.c_str(),mi.second.inode,mi.second.name.c_str());
	}
}

void dump(unsigned long long addr){
	unsigned char buf[81] = "";
	long long peek;
	for(int i = 0;i < 10; i++){
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT,child,addr+(PEEKSIZE*i),NULL);
		if(errno != 0) break;
		memcpy(&buf[i*PEEKSIZE],&peek,PEEKSIZE);
	}
	for(int line = 0;line < 5;line++){
		printf("\t%llx: ",addr+line*16);
		for(int i = 0;i < 16;i++){
			printf("%2.2x ",buf[i+line*16]);
		}
		printf(" |");
		for(int i = 0;i < 16;i++){
			if(isprint((int)buf[i+line*16])){
				printf("%c",buf[i+line*16]);
			}
			else{
				printf(".");
			}
		}
		printf("|\n");
	}
}

void single_step(){
	if(state != 2) err("** Process is not running");
	struct user_regs_struct regs;
	unsigned long long rip,code;
	int status;
	rip = ptrace(PTRACE_PEEKUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),0);
	code = ptrace(PTRACE_PEEKTEXT,child,rip,NULL) & 0xff;
	ptrace(PTRACE_SINGLESTEP,child,0,0);
	if(waitpid(child, &status, 0) < 0) errquit("waitpid");
	if(WIFEXITED(status) || WIFSIGNALED(status)){
		printf("** child process %d terminiated normally (code %d)\n",child,WEXITSTATUS(status));
		break_list.clear();
		state = 1;
		return;
	}
	else if(WIFSTOPPED(status)){
		if(find(rip) && code != 0xcc){
			instruction1 *inst = search(rip);
			code = 0;
			unsigned long long origin = ptrace(PTRACE_PEEKTEXT,child,rip,NULL);
			int size = (inst->size > PEEKSIZE)? PEEKSIZE:inst->size;
			memcpy(&code,inst->bytes,size);
			memcpy((unsigned char *)&code+size,(unsigned char *)&origin+size,PEEKSIZE-size);
			code = (code & 0xffffffffffffff00) | 0xcc;
			ptrace(PTRACE_POKETEXT,child,rip,code);
		}
		else if(find(rip)){
			instruction1 *inst = search(rip);
			code = 0;
			unsigned long long origin = ptrace(PTRACE_PEEKTEXT,child,rip,NULL);
			int size = (inst->size > PEEKSIZE)? PEEKSIZE:inst->size;
			memcpy(&code,inst->bytes,size);
			memcpy((unsigned char *)&code+size,(unsigned char *)&origin+size,PEEKSIZE-size);
			ptrace(PTRACE_POKETEXT,child,rip,code);
			ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),rip);
			printf("** breakpoint @\t");
			disassemble(rip,1,false);
		}

	}
}

void set_register(char *reg,unsigned long long value){
	if(state != 2) err("** Process is not running");
	struct user_regs_struct regs;
	if(strcmp(reg,"rax") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rax)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"rbx") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rbx)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"rcx") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rcx)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"rdx") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rdx)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"r8") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.r8)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"r9") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.r9)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"r10") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.r10)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"r11") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.r11)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"r12") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.r12)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"r13") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.r13)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"r14") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.r14)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"r15") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.r15)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"rdi") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rdi)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"rsi") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rsi)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"rbp") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rbp)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"rsp") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rsp)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"rip") == 0){
		struct user_regs_struct regs;
		unsigned long long rip,code;
		rip = ptrace(PTRACE_PEEKUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),0);
		code = ptrace(PTRACE_PEEKTEXT,child,rip,NULL) & 0xff;
		if(find(rip) && code != 0xcc){
			instruction1 *inst = search(rip);
			code = 0;
			unsigned long long origin = ptrace(PTRACE_PEEKTEXT,child,rip,NULL);
			int size = (inst->size > PEEKSIZE)? PEEKSIZE:inst->size;
			memcpy(&code,inst->bytes,size);
			memcpy((unsigned char *)&code+size,(unsigned char *)&origin+size,PEEKSIZE-size);
			code = (code & 0xffffffffffffff00) | 0xcc;
			ptrace(PTRACE_POKETEXT,child,rip,code);
		}
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.rip)-((unsigned char *)&regs),value);
	}
	if(strcmp(reg,"flags") == 0){
		ptrace(PTRACE_POKEUSER,child,((unsigned char *)&regs.eflags)-((unsigned char *)&regs),value);
	}
}

void help(){
	printf("- break {instruction-address}: add a break point\n");
	printf("- cont: continue execution\n");
	printf("- delete {break-point-id}: remove a break point\n");
	printf("- disasm addr: disassemble instructions in a file or a memory region\n");
	printf("- dump addr [length]: dump memory content\n");
	printf("- exit: terminate the debugger\n");
	printf("- get reg: get a single value from a register\n");
	printf("- getregs: show registers\n");
	printf("- help: show this message\n");
	printf("- list: list break points\n");
	printf("- load {path/to/a/program}: load a program\n");
	printf("- run: run the program\n");
	printf("- vmmap: show memory layout\n");
	printf("- set reg val: get a single value to a register\n");
	printf("- si: step into instruction\n");
	printf("- start: start the program and stop at the first instruction\n");
}

int main(int argc, char *argv[]) {
	setvbuf(stdout,NULL,_IONBF,0);
	setvbuf(stderr,NULL,_IONBF,0);
	FILE *fp = stdin;
	bool interactive = true;
	if(argc > 4){
		err("usage: ./hw4 [-s script] [program]");
	}
	else{
		if(argc == 2){
			load(argv[1]);
		}
		else if(argc == 3){
			if(strcmp(argv[1],"-s") != 0){
				err("usage: ./hw4 [-s script] [program]");
			}
			else{
				interactive = false;
				fp = fopen64(argv[2],"r");
			}
		}
		else if(argc == 4){
			if(strcmp(argv[1],"-s") != 0){
				err("usage: ./hw4 [-s script] [program]");
			}
			else{
				interactive = false;
				fp = fopen64(argv[2],"r");
				load(argv[3]);
			}
		}
	}
	char cmdline[128] = {0};
	char *cmds[3];
	if(interactive) fprintf(stderr,"sdb> ");
	while(fgets(cmdline,127,fp) != NULL){
		int count = 0;
		cmds[count] = strtok(cmdline," \t\r\n");
		while(cmds[count]){
			count++;
			cmds[count] = strtok(NULL," \t\r\n");
		}
		if(strcmp(cmds[0],"load") == 0){
			load(cmds[1]);
		}
		else if(strcmp(cmds[0],"start") == 0){
			start();
		}
		else if(strcmp(cmds[0],"run") == 0 || strcmp(cmds[0],"r") == 0){
			run();
		}
		else if(strcmp(cmds[0],"cont") == 0 || strcmp(cmds[0],"c") == 0){
			cont();
		}
		else if(strcmp(cmds[0],"break") == 0 || strcmp(cmds[0],"b") == 0){
			set_breakpoint(cmds[1]);
		}
		else if(strcmp(cmds[0],"delete") == 0){
			delete_breakpoint(cmds[1]);
		}
		else if(strcmp(cmds[0],"get") == 0 || strcmp(cmds[0],"g") == 0){
			get(cmds[1]);
		}
		else if(strcmp(cmds[0],"getregs") == 0){
			getregs();
		}
		else if(strcmp(cmds[0],"vmmap") == 0 || strcmp(cmds[0],"m") == 0){
			print_map();
		}
		else if(strcmp(cmds[0],"disasm") == 0 || strcmp(cmds[0],"d") == 0){
			if(count < 2){
				printf("** no addr given. \n");
			}
			else if(state == 2){
				disassemble(strtoull(cmds[1],NULL,16),10,true);
			}
			else{
				err("** Process is not running");
			}
		}
		else if(strcmp(cmds[0],"dump") == 0 || strcmp(cmds[0],"x") == 0){
			if(count < 2){
				printf("** no addr given. \n");
			}
			else if(state == 2){
				dump(strtoull(cmds[1],NULL,16));
			}
			else{
				err("** Process is not running");
			}
		}
		else if(strcmp(cmds[0],"list") == 0 || strcmp(cmds[0],"l") == 0){
			list_breakpoint();
		}
		else if(strcmp(cmds[0],"exit") == 0 || strcmp(cmds[0],"q") == 0){
			break;
		}
		else if(strcmp(cmds[0],"si") == 0){
			single_step();
		}
		else if(strcmp(cmds[0],"set") == 0 || strcmp(cmds[0],"s") == 0){
			set_register(cmds[1],strtoull(cmds[2],NULL,16));
		}
		else if(strcmp(cmds[0],"help") == 0 || strcmp(cmds[0],"h") == 0){
			help();
		}
		memset(cmdline,0,128);
		if(interactive) fprintf(stderr,"sdb> ");
	}
	printf("Bye.\n");
	fclose(fp);
	cs_close(&cshandle);
	return 0;
}

