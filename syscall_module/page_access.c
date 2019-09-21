#include <linux/kernel.h>
#include <asm/page.h>
#include <asm/pgtable_types.h>

#include "page_access.h"

char* level_desc[] = {	"PG_LEVEL_NONE",
                        "PG_LEVEL_4K",
                        "PG_LEVEL_2M",
                        "PG_LEVEL_1G",
                        "PG_LEVEL_512G",
                        "PG_LEVEL_NUM"
                    };

int make_page_writable(unsigned long addr)
{
    pte_t *pte;
    unsigned int level;

    pte = lookup_address(addr,&level);
    //printk(KERN_DEBUG "%s paging level %s\n", __func__, level_desc[level]);
    if (pte) {
        //printk(KERN_DEBUG "%s makeing page read/write\n",__func__);
        pte->pte |= _PAGE_RW;
        return 0;
    }
    //printk(KERN_DEBUG "%s failed to set write permission on the page\n", __func__);
    return 1;
}

int make_page_readonly(unsigned long addr)
{
    pte_t *pte;
    unsigned int level;

    pte = lookup_address(addr,&level);
    //printk(KERN_DEBUG "%s paging level %s\n", __func__, level_desc[level]);
    if (pte) {
        //printk(KERN_DEBUG "%s makeing page read only\n",__func__);
        pte->pte &= ~_PAGE_RW;
        return 0;
    }
    //printk(KERN_DEBUG "%s failed to set read only permission on the page\n", __func__);
    return 1;
}


