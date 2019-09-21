#ifndef __UTILS_H__
#define __UTILS_H__

void print_user_string(const char* prnt_func, const char* param_name, const char __user *str);
void print_user_short(const char* prnt_func, const char* param_name, unsigned short val);
void print_user_int(const char* prnt_func, const char* param_name, int val);

#endif
