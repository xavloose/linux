#ifndef __XALLOC_H
#define __XALLOC_H

void acl_free_all(void);
int acl_alloc_stack_init(unsigned long size);
void *acl_alloc(unsigned long len);
void *acl_alloc_num(unsigned long num, unsigned long len);

#endif