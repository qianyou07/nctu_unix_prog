#ifndef __PTOOLS_H__
#define __PTOOLS_H__

#include <sys/types.h>
#include <map>

typedef struct range_s {
	unsigned long begin, end;
}	range_t;

typedef struct map_entry_s {
	range_t range;
	int perm;
	std::string perm_str;
	long offset;
	unsigned long inode;
	std::string name;
}	map_entry_t;

bool operator<(range_t r1, range_t r2);
int load_maps(map<range_t, map_entry_t>& loaded);
#endif /* __PTOOLS_H__ */



class instruction1 {
public:
	unsigned char bytes[16];
	int size;
	std::string opr, opnd;
};

void errquit(const char *msg);
void err(const char *msg);
bool in_text(unsigned long long addr);
bool find(unsigned long long addr);
void load(char *path);
void start();
void run();
void cont();
void get(char *reg);
void getregs();
void print_map();
void set_breakpoint(char *addr);
void delete_breakpoint(char *id);
void list_breakpoint();
void dump(unsigned long long addr);
void single_step();
void set_register(char *reg,unsigned long long value);
void help();
instruction1 *search(unsigned long long addr);
void disassemble(unsigned long long addr,unsigned instr_count,bool check);
void print_instruction(long long addr, instruction1 *in);