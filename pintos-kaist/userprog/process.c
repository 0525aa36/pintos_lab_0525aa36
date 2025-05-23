#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
static void argument_stack (char **parse, int count, void **esp);
struct thread *get_child_by_tid(tid_t child_tid);
/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	
	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	char *save_ptr;
	char *token = strtok_r(file_name, " ", &save_ptr);
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (token, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
 tid_t
 process_fork (const char *name, struct intr_frame *if_) {
    struct thread *cur = thread_current ();
    memcpy(&cur->parent_if, if_, sizeof(struct intr_frame));

    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, cur);
    if (tid == TID_ERROR)
    	return TID_ERROR;

    struct thread *child = get_child_by_tid(tid);
    child->parent = cur;
     
    /* 자식 준비 신호 대기 */
    sema_down(&child->fork_sema);
	
	if(!child->fork_success)
		return TID_ERROR;

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if(!is_user_vaddr(va))
		return true;
	/* 2. Resolve VA from the parent's page map level 4. */
	// [2] 부모 프로세스의 페이지 테이블에서 해당 주소에 해당하는 물리 페이지 포인터를 얻음
    parent_page = pml4_get_page(parent->pml4, va);
    if (parent_page == NULL)
        return true;  // 해당 주소가 매핑되지 않았으면 복사할 필요 없음

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE . */
	// [3] 자식 프로세스를 위해 새 사용자 페이지 할당
    newpage = palloc_get_page(PAL_USER);
    if (newpage == NULL)
        return false;  // 메모리 부족으로 fork 실패
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE); 
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	 // [5] 해당 페이지가 writable인지 판단 (권한 복사 위해)
	writable = (*pte & PTE_W) != 0;
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		// 매핑 실패 시 페이지 할당 해제하고 false 반환
        palloc_free_page(newpage);
        return false;

	}
	return true; //정상 복사 완료
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	/* 0. 세마포어 초기화 (여기서 해도 되고, thread_init 에서 해도 됨) */
     sema_init(&current->fork_sema, 0);
     sema_init(&current->wait_sema, 0);
	 /* 1. 부모 컨텍스트 복사 */
     memcpy(&if_, &parent->parent_if, sizeof(struct intr_frame));

	/* 2. Duplicate page table */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.
	 *  - 부모의 메모리 복사
        - 부모의 fdt 복제
        - 부모의 intr_frame 복사
        - 부모가 자식이 준비될 때까지 sema_down()
        - 자식은 준비되면 sema_up()*/
	current->fdt = palloc_get_page(PAL_ZERO);
	if(current->fdt == NULL) goto error;

	for (int i = 0; i < FDCOUNT_LIMIT; i++)
         if (parent->fdt[i])
             current->fdt[i] = file_duplicate(parent->fdt[i]);
     current->fd_idx = parent->fd_idx;

	list_push_back(&parent->children, &current->child_elem);

	// 부모 깨움 (fork 완료 알림)
	current->fork_success = true;
	sema_up(&current->fork_sema);
    // 🔹 자식 프로세스 준비 완료 → do_iret로 유저모드 복귀
    do_iret(&if_);

error:
	current->fork_success = false;
	sema_up(&current->fork_sema);
    thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *cmd_line = f_name; // Renamed for clarity from file_name
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	// Argument parsing moved here from load()
	char *cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL) {
		return -1; // Cannot allocate memory for parsing
	}
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	char *token, *save_ptr;
	int argc = 0;
	char *argv[128]; // Max 128 arguments

	token = strtok_r(cmd_line_copy, " ", &save_ptr);
	if (token == NULL) { // Empty command line
		palloc_free_page(cmd_line_copy);
		return -1; // Error: empty command
	}
	char *prog_name = token; // First token is the program name

	argv[argc++] = prog_name;
	while ((token = strtok_r(NULL, " ", &save_ptr)) != NULL) {
		if (argc < 128) { // Ensure not to overflow argv
			argv[argc++] = token;
		} else {
			// Too many arguments, stop parsing.
			// The first 128 arguments will be passed.
			break;
		}
	}
	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (prog_name, &_if); // Pass only the program name to load

	// ...existing code...
    /* Setup stack with parsed arguments */
   if (success) {
        argument_stack(argv, argc, (void **)&_if.rsp); // _if.rsp가 argument_stack에 의해 업데이트됨
        
        // main 함수를 위해 argc와 argv를 레지스터에 설정
        _if.R.rdi = argc;          // argc를 %rdi에 설정
        _if.R.rsi = *(char ***)(_if.rsp + sizeof(void*) + sizeof(int)); // 스택에서 argv 주소를 읽어 %rsi에 설정
                                                                    // (_if.rsp는 가짜 반환 주소를 가리키므로,
                                                                    //  가짜 반환 주소와 argc를 건너뛰어야 argv 주소에 도달)

        // --- 추가된 printf 문 시작 ---
        // printf("---- Debug process_exec ----\n");
        // printf("_if.R.rdi (argc) = %d\n", (int)_if.R.rdi);
        // printf("_if.R.rsi (argv) = %p\n", (void *)_if.R.rsi);

        if (_if.R.rsi != NULL) {
            char **user_argv = (char **)_if.R.rsi;
            for (int i = 0; i < _if.R.rdi; i++) {
                // 사용자 공간 포인터이므로 직접 접근은 위험할 수 있으나,
                // 디버깅 목적으로 Pintos 커널 내에서 시도해볼 수 있습니다.
                // 실제 사용자 프로그램에서는 이 주소가 유효해야 합니다.
                // 여기서는 argv[i]가 가리키는 문자열의 주소와, 가능하다면 문자열 자체를 출력합니다.
                // 주의: user_argv[i]가 유효한 사용자 주소가 아니면 여기서 폴트가 발생할 수 있습니다.
                //       안전하게 하려면 커널에서 사용자 메모리를 읽는 함수를 사용해야 하지만,
                //       간단한 디버깅을 위해 직접 접근을 시도합니다.
                // printf("argv[%d] (address from _if.R.rsi): %p\n", i, (void *)user_argv[i]);
                // 만약 user_argv[i]가 커널에서 직접 접근 가능한 주소라면 (예: 물리적으로 매핑된 경우)
                // 또는 GDB로 이 값을 확인하는 것이 더 안전합니다.
                // printf("argv[%d] string: %s\n", i, user_argv[i]); // 이 줄은 폴트 가능성 있음
            }
        }
        

        /* For debugging: print stack contents */
        // hex_dump((uintptr_t)_if.rsp, _if.rsp, (uint8_t *)USER_STACK - (uint8_t *)_if.rsp, true);
    }

    /* Free the copy of the command line used for parsing */
// ...existing code...
	/* Free the copy of the command line used for parsing */
	palloc_free_page (cmd_line_copy);

	/* If load failed, quit. */
	/* The original cmd_line (f_name) is freed by process_exec ONLY if load fails. */
	if (!success) {
		palloc_free_page (cmd_line); 
		return -1;
	}

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	/*
	자식 목록에서 child_tid를 가진 thread 찾기

	이미 wait 한 자식이면 -1 리턴

	자식이 종료될 때까지 wait_sema로 기다리기

	자식의 exit_status 반환

	자식 리스트에서 제거
	*/
	for(int i = 0; i<2000000000; i++){}	
	return -1;
	// struct thread *cur = thread_current();
    // struct thread *child = get_child_by_tid(child_tid);

    // // (1) 존재하지 않거나, 자식이 아닌 경우
    // if (child == NULL || child->parent != cur)
    //     return -1;

    // // (2) 이미 기다렸던 자식인지 검사 (한 번만 기다릴 수 있음)
    // if (child->waited)
    //     return -1;
    // child->waited = true;

    // // (3) 자식이 종료될 때까지 기다림
    // sema_down(&child->wait_sema);

    // // (4) 자식의 종료 상태 얻기
    // int status = child->exit_status;

    // // (5) 자식 리스트에서 제거 (좀비 청소)
    // list_remove(&child->child_elem);

    // // (6) 자식 구조체는 thread_exit() 내부에서 free 될 것
    // return status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	// 🔹 부모가 존재한다면 wait_sema를 올려 깨움
    if (curr->parent != NULL)
        sema_up(&curr->wait_sema);  // 자식의 세마포어지만 부모가 기다리는 대상

	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) { // file_name is now just the program name
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name); // Use the passed file_name directly
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success) {
			if_->rsp = USER_STACK;
		} else {
			palloc_free_page (kpage);
		}
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

/* Puts the arguments on the stack. */
static void
argument_stack (char **parse, int count, void **esp) {
  // 주소를 저장할 배열
  void *argv_address[count];
  
  // 스택 포인터가 이미 USER_STACK에 설정되어 있다고 가정
  // 문자열 역순으로 저장 (마지막 인수부터 시작)
  for (int i = count - 1; i >= 0; i--) {
    size_t len = strlen(parse[i]) + 1; // null 문자 포함
    *esp -= len;
    memcpy(*esp, parse[i], len);
    argv_address[i] = *esp;
  }

  // 8바이트 정렬을 맞추기 위한 패딩 추가
  // 현재 스택 포인터를 8로 나누어 떨어지게 맞춤
  *esp = (void*)((uintptr_t)(*esp) & ~7UL);
  
  // argv[argc] = NULL 포인터 추가
  *esp -= sizeof(char*);
  *(char**)(*esp) = NULL;
  
  // 각 인수에 대한 포인터 저장 (역순)
  for (int i = count - 1; i >= 0; i--) {
    *esp -= sizeof(char*);
    *(char**)(*esp) = argv_address[i];
  }
  
  // argv 포인터 저장 (즉, argv[0]의 주소)
  void* argv_ptr = *esp;
  *esp -= sizeof(char**);
  *(char***)(*esp) = argv_ptr;
  
  // argc 저장
  *esp -= sizeof(int);
  *(int*)(*esp) = count;
  
  // 가짜 반환 주소 저장 
  *esp -= sizeof(void*);
  *(void**)(*esp) = NULL;
  
  // 디버깅을 위한 스택 범위 확인
  ASSERT((uintptr_t)*esp >= (uintptr_t)(((uint8_t *)USER_STACK) - PGSIZE)); 
}

struct thread *get_child_by_tid(tid_t child_tid) {
    struct thread *cur = thread_current();
    struct list_elem *e;

    for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)) {
        struct thread *t = list_entry(e, struct thread, child_elem);
        if (t->tid == child_tid)
            return t;
    }
    return NULL;
}

