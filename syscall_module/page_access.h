#ifndef __PAGE_ACCESS_H__
#define __PAGE_ACCESS_H__

int make_page_writable(unsigned long addr);
int make_page_readonly(unsigned long addr);

#endif
