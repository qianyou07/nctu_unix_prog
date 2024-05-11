#include <iostream>
#include <fstream>
#include <dirent.h>
#include <string>
#include <regex>
#include <vector>
#include <map>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <set>

using namespace std;

struct info{
	char command[30];
	char pid[8];
	char user[20];
};

char *last_name(char *str){
	int len = strlen(str);
	for(char *c = str + len - 1;c >= str;c--){
		if(!(*c >= 'a' && *c <='z') && !(*c >='A' && *c <= 'Z') && !(*c >= '0' && *c <= '9')){
			return c+1;
		}
	}
	return str;
}

void fill_info(char *dir_name,char *path,DIR *dir,struct info *target){
	strcpy(target->pid,dir_name);
	struct stat dir_stat;
	stat(path,&dir_stat);
	struct passwd *pw = getpwuid(dir_stat.st_uid);
	strcpy(target->user,pw->pw_name);
	struct dirent *inside_dir;
	while((inside_dir = readdir(dir)) != nullptr){
		char temp[100];
		strcpy(temp,path);
		strcat(temp,"/");
		strcat(temp,inside_dir->d_name);
		if(strcmp(inside_dir->d_name,"comm") == 0){
			char buf[500];
			fstream fp;
			fp.open(temp,ios::in);
			fp.getline(buf,sizeof(buf),'\n');
			strcpy(target->command,buf);
			fp.close();
		}
	}
}

void find_type(char *path,char *buf,struct stat *dir_stat){
	if(stat(path,dir_stat) == -1){
		strcpy(buf,"unknown");
	}
	else if(S_ISDIR(dir_stat->st_mode)){
		strcpy(buf,"DIR");
	}
	else if(S_ISREG(dir_stat->st_mode)){
		strcpy(buf,"REG");
	}
	else if(S_ISCHR(dir_stat->st_mode)){
		strcpy(buf,"CHR");
	}
	else if(dir_stat->st_mode & S_IFIFO){
		strcpy(buf,"FIFO");
	}
	else if(S_ISSOCK(dir_stat->st_mode)){
		strcpy(buf,"SOCK");
	}
	else{
		strcpy(buf,"unknown");
	}
}

void find_fd(char *path,char *buf){
	fstream fp;
	fp.open(path,ios::in);
	string f_mode;
	fp>>f_mode>>f_mode>>f_mode>>f_mode;
	if(f_mode[f_mode.size()-1] == '2'){
		strcpy(buf,last_name(path));
		strcat(buf,"u");
	}
	else if(f_mode[f_mode.size()-1] == '1'){
		strcpy(buf,last_name(path));
		strcat(buf,"w");
	}
	else if(f_mode[f_mode.size()-1] == '0'){
		strcpy(buf,last_name(path));
		strcat(buf,"r");
	}
	fp.close();
}

int main(int argc,char *argv[]){
	map<char *,struct info *> table;
	DIR *outside_dir,*inside_dir;
	struct dirent *dir_read;
	vector<char *> files;
	int mode;
	bool c_mode = false,t_mode = false,f_mode = false;
	int c_pos,t_pos,f_pos;
	if(argc % 2 == 0) return 0;
	for(int i = 1;i < argc;i += 2){
		if(strcmp(argv[i],"-c") == 0){
			c_mode = true;
			c_pos = i + 1;
		}
		else if(strcmp(argv[i],"-t") == 0){
			if(strcmp(argv[i+1],"REG") != 0 && strcmp(argv[i+1],"CHR") != 0 && strcmp(argv[i+1],"DIR") != 0 && strcmp(argv[i+1],"FIFO") != 0 &&
				strcmp(argv[i+1],"SOCK") != 0 && strcmp(argv[i+1],"unknown") != 0){
					cout<<"Invalid TYPE option."<<endl;
					return 0;
			}
			t_mode = true;
			t_pos = i + 1;
		}
		else if(strcmp(argv[i],"-f") == 0){
			f_mode = true;
			f_pos = i + 1;
		}
		else{
			return 0;
		}
	}
	if((outside_dir = opendir("/proc")) != nullptr){
		cout<<"COMMAND\t\tPID\tUSER\t\tFD\tTYPE\tNODE\t\tNAME\n";
		regex reg("[0-9]+"); //Find the files that contains only digit.
		while((dir_read = readdir(outside_dir)) != nullptr){
			if(regex_match(dir_read->d_name,reg)){
				string path(dir_read->d_name);
				path = "/proc/" + path;
				char *file = dir_read->d_name;
				if((inside_dir = opendir(path.c_str())) != nullptr){
					table[file] = new struct info;
					fill_info(file,(char *)path.c_str(),inside_dir,table[file]);
					closedir(inside_dir);
				}
				if(c_mode){
					regex rule(argv[c_pos]);
					if(!regex_search(table[file]->command,rule))
						continue;
				}
				inside_dir = opendir(path.c_str());
				char cwd_out[2000]={0},root_out[2000]={0},exe_out[2000]={0},mem_out[50000]={0},fd_out[100000]={0};
				while((dir_read = readdir(inside_dir)) != nullptr){
					char temp[100];
					strcpy(temp,path.c_str());
					strcat(temp,"/");
					strcat(temp,dir_read->d_name);
					if(strcmp(dir_read->d_name,"cwd") == 0 || strcmp(dir_read->d_name,"root") == 0 || strcmp(dir_read->d_name,"exe") == 0){
						struct stat *dir_stat = new struct stat;
						char type[10] = {0};
						find_type(temp,type,dir_stat);
						if(t_mode){
							if(strcmp(type,argv[t_pos]) != 0)
								continue;
						}
						char fd[10] = {0};
						strcpy(fd,dir_read->d_name);
						char buf[200] = {0};
						char *target_out;
						if(strcmp(dir_read->d_name,"cwd") == 0){
							target_out = cwd_out;
						}
						else if(strcmp(dir_read->d_name,"root") == 0){
							target_out = root_out;
						}
						else if(strcmp(dir_read->d_name,"exe") == 0){
							target_out = exe_out;
						}
						if(readlink(temp,buf,200-1) != -1){
							if(f_mode){
								char origin_name[200] = {0};
								char *loc;
								if((loc = strstr(buf,"(deleted)")) != NULL){
									strncpy(origin_name,buf,loc-buf);
								}
								else{
									strcpy(origin_name,buf);
								}
								regex rule(argv[f_pos]);
								if(!regex_search(origin_name,rule))
									continue;
							}
							strcat(target_out,table[file]->command);
							strcat(target_out,"\t\t");
							strcat(target_out,table[file]->pid);
							strcat(target_out,"\t");
							strcat(target_out,table[file]->user);
							strcat(target_out,"\t\t");
							strcat(target_out,fd);
							strcat(target_out,"\t");
							strcat(target_out,type);
							strcat(target_out,"\t");
							strcat(target_out,to_string(dir_stat->st_ino).c_str());
							strcat(target_out,"\t\t");
							strcat(target_out,buf);
							strcat(target_out,"\n");
							// cout<<table[file]->command<<"\t\t"<<table[file]->pid<<"\t"<<table[file]->user<<"\t\t"<<fd<<"\t"<<type<<"\t"<<dir_stat->st_ino<<"\t\t"<<buf<<endl;
						}
						else{
							if(f_mode){
								regex rule(argv[f_pos]);
								if(!regex_search(temp,rule))
									continue;
							}
							strcat(target_out,table[file]->command);
							strcat(target_out,"\t\t");
							strcat(target_out,table[file]->pid);
							strcat(target_out,"\t");
							strcat(target_out,table[file]->user);
							strcat(target_out,"\t\t");
							strcat(target_out,dir_read->d_name);
							strcat(target_out,"\t");
							strcat(target_out,type);
							strcat(target_out,"\t\t\t");
							strcat(target_out,temp);
							strcat(target_out," (readlink: Permission denied)\n");
							// cout<<table[file]->command<<"\t\t"<<table[file]->pid<<"\t"<<table[file]->user<<"\t\t"<<dir_read->d_name<<"\t"<<type<<"\t\t\t"<<temp<<" (readlink: Permission denied)"<<endl;
						}
					}
					else if(strcmp(dir_read->d_name,"maps") == 0){
						char buf[500];
						fstream fp;
						fp.open(temp,ios::in);
						set<string> has_print;
						if(fp){
							while(fp.getline(buf,sizeof(buf),'\n')){
								vector<string> token;
								char *word;
								word = strtok(buf," ");
								while(word){
									string s(word);
									token.push_back(s);
									word = strtok(NULL," ");
								}
								if(token.size() == 6 && token[4] != "0" && has_print.find(token[4]) == has_print.end()){
									struct stat *dir_stat = new struct stat;
									char type[10] = {0};
									char fd[10] = {0};
									strcpy(fd,"mem");
									find_type((char *)token[5].c_str(),type,dir_stat);
									if(strstr(token[5].c_str(),"(deleted)") != NULL){
										memset(fd,'\0',10);
										strcpy(fd,"del");
										memset(type,'\0',10);
										strcpy(type,"unknown");
									}
									if(t_mode){
										if(strcmp(type,argv[t_pos]) != 0)
											continue;
									}
									has_print.insert(token[4]);
									if(f_mode){
										char modify_name[200] = {0};
										strcpy(modify_name,token[5].c_str());
										char origin_name[200] = {0};
										char *loc;
										if((loc = strstr(modify_name,"(deleted)")) != NULL){
											strncpy(origin_name,modify_name,loc-modify_name);
										}
										else{
											strcpy(origin_name,modify_name);
										}
										regex rule(argv[f_pos]);
										if(!regex_search(origin_name,rule))
											continue;
									}
									strcat(mem_out,table[file]->command);
									strcat(mem_out,"\t\t");
									strcat(mem_out,table[file]->pid);
									strcat(mem_out,"\t");
									strcat(mem_out,table[file]->user);
									strcat(mem_out,"\t\t");
									strcat(mem_out,fd);
									strcat(mem_out,"\t");
									strcat(mem_out,type);
									strcat(mem_out,"\t");
									strcat(mem_out,token[4].c_str());
									strcat(mem_out,"\t\t");
									strcat(mem_out,token[5].c_str());
									strcat(mem_out,"\n");
									// cout<<table[file]->command<<"\t\t"<<table[file]->pid<<"\t"<<table[file]->user<<"\t\t"<<fd<<"\t"<<type<<"\t"<<token[4]<<"\t\t"<<token[5]<<endl;
								}
							}
							fp.close();
						}
					}
					else if(strcmp(dir_read->d_name,"fd") == 0){
						DIR *fd_dir;
						if((fd_dir = opendir(temp)) != NULL){
							struct dirent *fd_dir_read;
							while((fd_dir_read = readdir(fd_dir)) != nullptr){
								if(!regex_search(fd_dir_read->d_name,reg)) continue;
								struct stat *dir_stat = new struct stat;
								char fd_path[50] = {0};
								char fdinfo_path[50] = {0};
								char fd[10] = {0};
								char type[10] = {0};
								char name[200] = {0};
								strcpy(fd_path,temp);
								strcat(fd_path,"/");
								strcat(fd_path,fd_dir_read->d_name);
								strncpy(fdinfo_path,temp,strlen(temp)-2);
								strcat(fdinfo_path,"fdinfo/");
								strcat(fdinfo_path,fd_dir_read->d_name);
								find_fd(fdinfo_path,fd);
								find_type(fd_path,type,dir_stat);

								readlink(fd_path,name,200-1);
								if(strstr(name,"(deleted)") != NULL){
									memset(type,'\0',10);
									strcpy(type,"unknown");
								}
								if(t_mode){
									if(strcmp(type,argv[t_pos]) != 0)
										continue;
								}
								if(f_mode){
									char origin_name[200] = {0};
									char *loc;
									if((loc = strstr(name,"(deleted)")) != NULL){
										strncpy(origin_name,name,loc-name);
									}
									else{
										strcpy(origin_name,name);
									}
									regex rule(argv[f_pos]);
									if(!regex_search(origin_name,rule))
										continue;
								}
								strcat(fd_out,table[file]->command);
								strcat(fd_out,"\t\t");
								strcat(fd_out,table[file]->pid);
								strcat(fd_out,"\t");
								strcat(fd_out,table[file]->user);
								strcat(fd_out,"\t\t");
								strcat(fd_out,fd);
								strcat(fd_out,"\t");
								strcat(fd_out,type);
								strcat(fd_out,"\t");
								strcat(fd_out,to_string(dir_stat->st_ino).c_str());
								strcat(fd_out,"\t\t");
								strcat(fd_out,name);
								strcat(fd_out,"\n");
								// cout<<table[file]->command<<"\t\t"<<table[file]->pid<<"\t"<<table[file]->user<<"\t\t"<<fd<<"\t"<<type<<"\t"<<dir_stat->st_ino<<"\t\t"<<name<<endl;
							}
							closedir(fd_dir);
						}
						else{
							if(t_mode)
								continue;
							if(f_mode){
								regex rule(argv[f_pos]);
								if(!regex_search(temp,rule))
									continue;
							}
							strcat(fd_out,table[file]->command);
							strcat(fd_out,"\t\t");
							strcat(fd_out,table[file]->pid);
							strcat(fd_out,"\t");
							strcat(fd_out,table[file]->user);
							strcat(fd_out,"\t\tNOFD\t\t\t\t");
							strcat(fd_out,temp);
							strcat(fd_out," (opendir: Permission denied)\n");
							// cout<<table[file]->command<<"\t\t"<<table[file]->pid<<"\t"<<table[file]->user<<"\t\tNOFD\t\t\t\t"<<temp<<" (opendir: Permission denied)"<<endl;
						}
					}
				}
				cout<<cwd_out<<root_out<<exe_out<<mem_out<<fd_out;
			}

		}
	}
	closedir(outside_dir);
	return 0;
}