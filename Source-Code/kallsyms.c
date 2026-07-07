/* kallsyms.c: Stub implementation that forces fallback to /proc/kallsyms path
 * The original in-process parser wasn't available in the repo, so we use the simpler fallback */

#include <stddef.h>

static int (*ks_pread)(unsigned long pa, void *buf, unsigned long len);

void ks_set_read(int (*rd)(unsigned long pa, void *buf, unsigned long len))
{
    ks_pread = rd;
}

/* Return failure to force fallback to /proc/kallsyms path */
int ks_resolve(unsigned long kbase, unsigned long ktext_va)
{
    return -1;  /* Force fallback */
}

unsigned long ks_sym(const char *name)
{
    return 0;  /* Not found */
}
