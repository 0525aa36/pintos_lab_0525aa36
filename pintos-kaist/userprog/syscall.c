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
#include "threads/synch.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// syscall_handler 위에 함수 프로토타입 선언 추가
static void halt(void);
static int write(int fd, const void *buffer, unsigned size);
static void exit(int status);
static bool create(const char *file, unsigned initial_size);
static int open(const char *file);
static void close(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);
static bool remove(const char *file);
static int filesize(int fd);
static unsigned tell(int fd);
static void seek(int fd, unsigned position);
static void check_address(const void *addr);
struct lock filesys_lock;
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
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit((int)f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read((int)f->R.rdi, (void *)f->R.rsi, (unsigned)f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write((int)f->R.rdi, (const void *)f->R.rsi, (unsigned)f->R.rdx);
            break;
        case SYS_EXEC:
            break;
        case SYS_WAIT:
            break;
        case SYS_CREATE:
            f->R.rax = create((const char *)f->R.rdi, (unsigned)f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove((const char *)f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open((const char *)f->R.rdi);
            break;
        case SYS_CLOSE:
            close((int)f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize((int)f->R.rdi);
            break;
        case SYS_SEEK:
            seek((int)f->R.rdi, (unsigned)f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell((int)f->R.rdi);
            break;
        default:
            exit(-1); // 알 수 없는 시스템콜은 종료
    }
	// printf ("system call!\n");
	// thread_exit ();
}

static void
halt(void) {
    power_off(); // 시스템 종료
}

static void
exit(int status) {
    struct thread *cur = thread_current();
    
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

static int
write(int fd, const void *buffer, unsigned size) {
    check_address(buffer); // 사용자 주소인지 확인

    struct thread *cur = thread_current();
    int bytes_written = -1;

    lock_acquire(&filesys_lock);
    if (fd == 1) {
        // STDOUT (콘솔 출력)
        putbuf(buffer, size); // 콘솔에 출력
        bytes_written = size;
    } else if (fd > 1 && fd < FDCOUNT_LIMIT && cur->fdt[fd]) {
        // 일반 파일 쓰기
        bytes_written = file_write(cur->fdt[fd], buffer, size);
    }
    lock_release(&filesys_lock);

    return bytes_written;
}

static bool
create(const char *file, unsigned initial_size) {
    check_address(file); // 사용자 주소인지 확인
    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}

static int
open(const char *file) {
    check_address(file);
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }

    struct thread *cur = thread_current();
    int fd = cur->fd_idx;
    while (fd < FDCOUNT_LIMIT && cur->fdt[fd] != NULL) {
        fd++;
    }
    if (fd >= FDCOUNT_LIMIT) {
        file_close(f);
        lock_release(&filesys_lock);
        return -1;
    }

    cur->fdt[fd] = f;
    cur->fd_idx = fd + 1;
    lock_release(&filesys_lock);
    return fd;
}

static void
close(int fd) {
    struct thread *cur = thread_current();
    if (fd < 2 || fd >= FDCOUNT_LIMIT || cur->fdt[fd] == NULL) return;

    lock_acquire(&filesys_lock);
    file_close(cur->fdt[fd]);
    cur->fdt[fd] = NULL;
    lock_release(&filesys_lock);
}

static int
read(int fd, void *buffer, unsigned size) {
    check_address(buffer); // 사용자 주소인지 확인

    struct thread *cur = thread_current();
    int bytes_read = -1;

    lock_acquire(&filesys_lock);
    if (fd == 0) {
        // STDIN (키보드 입력)
        uint8_t *buf = buffer;
        for (unsigned i = 0; i < size; i++) {
            buf[i] = input_getc(); // 키보드에서 한 글자씩 입력
        }
        bytes_read = size;
    } else if (fd > 1 && fd < FDCOUNT_LIMIT && cur->fdt[fd]) {
        // 일반 파일 읽기
        bytes_read = file_read(cur->fdt[fd], buffer, size);
    }
    lock_release(&filesys_lock);

    return bytes_read;
}

static void
seek(int fd, unsigned position) {
    struct thread *cur = thread_current();
    if (fd < 2 || fd >= FDCOUNT_LIMIT || cur->fdt[fd] == NULL) return;

    lock_acquire(&filesys_lock);
    file_seek(cur->fdt[fd], position);
    lock_release(&filesys_lock);
}

static unsigned
tell(int fd) {
    struct thread *cur = thread_current();
    if (fd < 2 || fd >= FDCOUNT_LIMIT || cur->fdt[fd] == NULL) return -1;

    lock_acquire(&filesys_lock);
    unsigned pos = file_tell(cur->fdt[fd]);
    lock_release(&filesys_lock);

    return pos;
}

static int
filesize(int fd) {
    struct thread *cur = thread_current();
    if (fd < 2 || fd >= FDCOUNT_LIMIT || cur->fdt[fd] == NULL) return -1;

    lock_acquire(&filesys_lock);
    int length = file_length(cur->fdt[fd]);
    lock_release(&filesys_lock);

    return length;
}

static bool
remove(const char *file) {
    check_address(file); // 주소 검증

    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file);
    lock_release(&filesys_lock);

    return success;
}

/* 유효 주소 체그 함수*/
static void
check_address(const void *addr) {
    if (addr == NULL || !is_user_vaddr(addr) ||
        pml4_get_page(thread_current()->pml4, addr) == NULL) {
        exit(-1);
    }
}