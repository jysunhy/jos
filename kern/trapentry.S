/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>



###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
TRAPHANDLER_NOEC(handler_divide, T_DIVIDE);
TRAPHANDLER_NOEC(handler_debug, T_DEBUG);
TRAPHANDLER_NOEC(handler_nmi, T_NMI);
TRAPHANDLER_NOEC(handler_brkpt, T_BRKPT);
TRAPHANDLER_NOEC(handler_oflow, T_OFLOW);
TRAPHANDLER_NOEC(handler_bound, T_BOUND);
TRAPHANDLER_NOEC(handler_illop, T_ILLOP);
TRAPHANDLER_NOEC(handler_device, T_DEVICE);
TRAPHANDLER(handler_dblflt,T_DBLFLT);

TRAPHANDLER(handler_tss, T_TSS);
TRAPHANDLER(handler_segnp, T_SEGNP);
TRAPHANDLER(handler_stack, T_STACK);
TRAPHANDLER(handler_gpflt, T_GPFLT);
TRAPHANDLER(handler_pgflt, T_PGFLT);

TRAPHANDLER_NOEC(handler_fperr, T_FPERR);
TRAPHANDLER(handler_align, T_ALIGN);
TRAPHANDLER_NOEC(handler_mchk, T_MCHK);
TRAPHANDLER_NOEC(handler_simderr, T_SIMDERR);
TRAPHANDLER_NOEC(handler_syscall, T_SYSCALL);



.globl sysenter_handler;
.type sysenter_handler, @function;
.align 2;
sysenter_handler:
/*
 * Lab 3: Your code here for system call handling
 */
	pushw $0x0
	pushw $GD_UD | 3
	pushl %ebp
	pushfl

	pushw $0x0
	pushw $GD_UT | 3
	pushl %esi
	pushl $0
	pushl $0

	pushw $0x0

	pushw %ds

	pushw $0x0
	pushw %es

	pushal

	mov $GD_KD, %ax
	mov %ax, %ds
	mov %ax, %es
	
	pushl %esp

	call _syscall

	popl %esp

	popal

	popl %es

	popl %ds

	movl %ebp, %ecx
	movl %esi, %edx

	sysexit


/*
 * Lab 3: Your code here for _alltraps
 */
_alltraps:
	pushl %ds
	pushl %es
	pushal

	movw $GD_KD, %ax
	movw %ax, %ds
	movw %ax, %es

	pushl %esp
	call trap
	add $4, %esp

