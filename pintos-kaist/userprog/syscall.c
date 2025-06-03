#include "userprog/syscall.h"
#include <stdio.h>
#include "include/lib/kernel/stdio.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "include/threads/synch.h"
#include "devices/input.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_user(const void *);
void check_user_buffer(const void *, size_t);
bool sys_create(const char *, unsigned int);
int sys_open (const char *);
bool check_fd_table(int);
void sys_close(int );
void sys_halt (void);
int sys_write(int , const void *, unsigned);
void sys_exit (int);
tid_t sys_fork (const char *, struct intr_frame *);
tid_t sys_exec (const char*);
int sys_read(int, void *, unsigned);
int sys_filesize(int);
int sys_wait(tid_t);
bool sys_remove (const char *);

struct lock file_lock; // file lock

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	
	switch (f->R.rax)
	{
		case SYS_HALT:
			sys_halt();
			break;
		case SYS_EXEC:
			f->R.rax = sys_exec(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = sys_open(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = sys_wait(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_FILESIZE:
			f->R.rax = sys_filesize(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = sys_create(f->R.rdi, f->R.rsi);
			break;
		case SYS_CLOSE:
			sys_close(f->R.rdi);
			break;
		case SYS_REMOVE:
			f->R.rax = sys_remove(f->R.rdi);
			break;
		case SYS_SEEK:
			sys_seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_FORK:
			f->R.rax = sys_fork(f->R.rdi, f);
			break;
		case SYS_WRITE:
			f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);	
			break;
		case SYS_EXIT:
			sys_exit(f->R.rdi);
			break;
		default:
			sys_exit(-1);
			break;
	}

	// printf ("system call!\n");
	//
	
}

// 유저 주소 체크 함수
void 
check_user(const void *uaddr){
	if (uaddr == NULL || is_kernel_vaddr(uaddr) || 
		pml4_get_page(thread_current()->pml4, uaddr) == NULL){
		sys_exit(-1);
	}
}

void
check_user_buffer(const void *uaddr, size_t size) {
	uint8_t *start = (uint8_t *) uaddr;
	uint8_t *end = start + size;

	while (start < end) {
		if (!is_user_vaddr(start) || 
			pml4_get_page(thread_current()->pml4, start) == NULL)
			sys_exit(-1);

		// 다음 페이지 경계로 이동
		start = pg_round_down(start) + PGSIZE;
	}
}

bool 
sys_remove (const char *file){
	check_user(file);

	lock_acquire(&file_lock);
	bool status = filesys_remove(file);
	lock_release(&file_lock);

	return status;
}

int
sys_filesize(int fd){
	struct thread *cur = thread_current();

	if ((FD_START > fd) || (fd >= FD_MAX) 
		|| (thread_current()->fd_table[fd] == NULL))
		return -1;

	lock_acquire(&file_lock);
	int size = file_length(thread_current()->fd_table[fd]);
	lock_release(&file_lock);

	return size;
}

void
sys_seek(int fd, unsigned position){
	if(fd < 2){
		return;
	}

	struct thread *curr = thread_current();
	struct file *f = curr->fd_table[fd];

	if(f == NULL){
		return;
	}

	lock_acquire(&file_lock);
	file_seek(f, position);
	lock_release(&file_lock);
}

int
sys_wait(tid_t child_tid){
	return process_wait(child_tid);
}

bool 
sys_create(const char *file, unsigned int initial_size) {
	check_user(file);

	lock_acquire(&file_lock);
	bool is_create = filesys_create(file, initial_size);
	lock_release(&file_lock);

	return is_create;
}

int
sys_open (const char *file){
	check_user(file);

	lock_acquire(&file_lock);
	struct file *f = filesys_open(file);
	lock_release(&file_lock);

    if (f == NULL) return -1;
	
	struct thread *curr = thread_current();

	for (int fd = FD_START; fd < FD_MAX; fd++) {
		if (curr->fd_table[fd] == NULL) {
			curr->fd_table[fd] = f;
			return fd;
		}
	}

	/* FD 테이블이 가득 찼다면 열린 파일을 반드시 닫아 준다. */
    lock_acquire (&file_lock);
    file_close (f);
    lock_release (&file_lock);
	return -1;
}


bool 
check_fd_table(int fd){
	if ((FD_START <= fd) && (fd < FD_MAX) 
		&& (thread_current()->fd_table[fd] != NULL))
		return true;
	return false;
}

void 
sys_close(int fd) {
	if(!check_fd_table(fd))
		return;

	struct file *f = thread_current()->fd_table[fd];

	if (f == NULL)
		return;

	lock_acquire(&file_lock);
    file_close(f);
	lock_release(&file_lock);

    thread_current()->fd_table[fd] = NULL;
}

void 
sys_halt (void){
	power_off();
}

int
sys_write(int fd, const void *buffer, unsigned size){
	check_user_buffer(buffer, size); // 유저 버퍼 체크
	struct thread *cur = thread_current ();

	if(fd == 1){
		lock_acquire(&file_lock);
		putbuf((char *)buffer, (size_t)size);
		lock_release(&file_lock);
		return size;
	}

	if((fd >= FD_START) && (fd < FD_MAX) && (cur->fd_table[fd] != NULL)){
		struct file *openfile = cur->fd_table[fd];
		lock_acquire(&file_lock);
		int w_size = file_write(openfile, (void *)buffer, (off_t)size);
		lock_release(&file_lock);
		return w_size;
	}

	sys_exit(-1);
}

int sys_read(int fd, void *buffer, unsigned size){
	check_user_buffer(buffer, size); // 유저 버퍼 체크
	struct thread *cur = thread_current ();

	if(fd == 0){
		for (int i = 0; i < (int) size; i++){
			char *buf = (char *) buffer;
			buf[i] = input_getc();
		}
		return size;
	}

	if(fd >= FD_START && fd < FD_MAX){
		struct file *openfile = cur->fd_table[fd];

		if (openfile == NULL)
			sys_exit(-1);

		lock_acquire(&file_lock);
		int r_size = file_read(openfile, buffer, size);
		lock_release(&file_lock);
		return r_size;
	}

	sys_exit(-1);
}

void 
sys_exit (int status){
	struct thread *cur = thread_current ();
	if (cur->my_info != NULL) {
    	cur->my_info->exit_status = status;
	}
	
	printf ("%s: exit(%d)\n", cur->name, status);
	
	thread_exit ();
}

tid_t
sys_fork (const char *thread_name, struct intr_frame *if_ UNUSED){
	return process_fork(thread_name, if_);
}

tid_t
sys_exec (const char *cmd_line){
	check_user(cmd_line);

	if (process_exec(cmd_line) == -1){
		sys_exit(-1);
	}

	return thread_current()->tid;
}
