// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display information of current stack", mon_backtrace },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

    // And you must use the "cprintf" function with %n specifier
    // you augmented in the "Exercise 9" to do this job.

    // hint: You can use the read_pretaddr function to retrieve 
    //       the pointer to the function call return address;

    char str[256] = {};
    int nstr = 0;
    char *pret_addr;
    // Your code here.
    uint32_t ebp,
             ret_addr; 
    pret_addr = (char *)read_pretaddr();

    /*
        ret_addr is the address at which this function call should return
    */
    ret_addr =  *(uint32_t*)pret_addr;
    


    /*
        modify the return address to execute the injected instruction started at str+1
    */
    //*((int *)pret_addr) = (int)(str+1);
    for(nstr=0;nstr<256;nstr++)
        str[nstr]='0';
    int tmp = (int)(str + 1);
    str[tmp&0xff]='\0';
    cprintf("%s%n",str,pret_addr);    
    str[tmp&0xff]='0';
    str[(tmp>>8)&0xff]='\0';
    cprintf("%s%n",str,pret_addr+1);    
    str[(tmp>>8)&0xff]='0';
    str[(tmp>>16)&0xff]='\0';
    cprintf("%s%n",str,pret_addr+2);    
    str[(tmp>>16)&0xff]='0';
    str[(tmp>>24)&0xff]='\0';
    cprintf("%s%n",str,pret_addr+3);    
    str[(tmp>>24)&0xff]='0';

    /***********************************/
    /* inject code in str              */
    /* range  content                  */
    /* 0:0    \0                       */
    /* 1:5    push ret_addr            */
    /* 6:10   jmp do_overflow          */
    /***********************************/

    /* 
        str[0] = 0 for print usage 
    */
    str[0] = 0;


    /* 
       push ret_addr
    */
    str[1]=0x68;  //op code for push
    *(int *)(str+2)=ret_addr;

    /* 
       jmp do_overflow 
    */
    str[6]=0xe9;  //op code for jmp
    *(int*)(str+7)=(int)do_overflow-(int)(str+6)-5; //jmp from str+6 to do_overflow

    //avoid optimization of str
    cprintf("%s\n",str);
}

void
overflow_me(void)
{
        start_overflow();
}

void print_stack_info(uint32_t ebp) {
        static int level = 0;
        uint32_t last_ebp, eip;
        struct Eipdebuginfo info;
        int i;
        if(ebp==0)
           return;
        if(level==0) {
            cprintf("Stack backtrace:\n");
        }
        level++;
        eip = *(uint32_t*)(ebp+4);
        last_ebp = *(uint32_t*)(ebp);
        debuginfo_eip(eip,&info);

        cprintf("  ebp %x  ", ebp);
        cprintf("eip %x  ", eip);
        cprintf("args");
        //for(i = 0; i < info.eip_fn_narg; i++)
        for(i = 0; i < 5; i++)
            cprintf(" %08x",*(((uint32_t *)ebp)+2+i));
        cprintf("\n");
        cprintf("         %s:%d: %s+%u\n",info.eip_file,info.eip_line,info.eip_fn_name,eip-info.eip_fn_addr);
        print_stack_info(last_ebp);
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    // Your code here.
    overflow_me();
    uint32_t ebp = read_ebp();
    print_stack_info(ebp);
    cprintf("Backtrace success\n");
    return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
