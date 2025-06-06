/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* 초기화 함수(initializer)를 사용하여 대기 중인 페이지 객체(pending page object)를 생성합니다. 
 * 페이지를 직접 생성하지 말고, 반드시 이 함수나 vm_alloc_page를 통해 생성해야 합니다.*/
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
	/* 위의 함수는 초기화되지 않은 주어진 type의 페이지를 생성합니다. 
	초기화되지 않은 페이지의 swap_in 핸들러는 자동적으로 페이지 타입에 맞게 페이지를 초기화하고 
	주어진 AUX를 인자로 삼는 INIT 함수를 호출합니다. 
	당신이 페이지 구조체를 가지게 되면 프로세스의 보조 페이지 테이블에 그 페이지를 삽입하십시오. 
	vm.h에 정의되어 있는 VM_TYPE 매크로를 사용하면 편리할 것입니다. */

	ASSERT (VM_TYPE(type) != VM_UNINIT);

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check whether the upage is already occupied or not. */
	/* 해당 upage(사용자 가상 주소)가 이미 사용 중인지 확인합니다.*/
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: 페이지를 생성하고, VM 타입에 따라 적절한 initializer를 가져온 뒤, 
		 * uninit_new를 호출하여 "uninit" 페이지 구조체를 생성하세요. 
		 * uninit_new 호출 이후에는 해당 구조체의 필드를 수정해야 합니다. */
		//////////////////////////////////////////////////////////////////////////////
		struct page * page = (struct page*)malloc(sizeof(struct page));
		
		bool (*initializer)(struct page*, enum vm_type, void *);
		
		if(VM_TYPE(type) == VM_ANON){
			initializer = anon_initializer;
		}
		else if(VM_TYPE(type) == VM_FILE){
			initializer = file_backed_initializer;
		}
		else{
			goto err;
		}
		uninit_new(page, upage, init, type, aux, initializer);
		page->writable = writable;

		bool res = spt_insert_page(spt, page);


		struct page *result = spt_find_page(spt, upage);
		if (result == NULL){
			goto err ;
		}
		return true;
	

		//////////////////////////////////////////////////////////////////////////////


		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */ ////?????
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page p;
	struct hash_elem *e;
	/* TODO: Fill this function. */
	p.va = pg_round_down(va);

	e = hash_find(&spt->hash_spt, &p.hash_elem);

	if(e==NULL){
		return NULL;
	}

	return hash_entry(e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */ 
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	/* TODO: Fill this function. */
	struct hash_elem *e = hash_insert(&spt->hash_spt, &page->hash_elem);
	if (e == NULL){
		return true;
	}
	else{
		return false;
	}
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/

/* palloc()을 호출하여 프레임을 가져온다. 만약 사용 가능한 페이지가 없다면,
 * 페이지를 쫓아내고(evict) 그것을 반환한다. 이 함수는 항상 유효한 주소를 반환한다.
 * 즉, 사용자 풀 메모리가 가득 찬 경우에는, 이 함수가 프레임을 쫓아내어
 * 사용 가능한 메모리 공간을 확보한다. */

static struct frame *
vm_get_frame (void) { //???
	struct frame *frame = malloc(sizeof(struct frame));
	/* TODO: Fill this function. */
	ASSERT (frame != NULL);

	frame->kva = palloc_get_page(PAL_USER);
	// ASSERT (frame->page == NULL);
	if(frame->kva == NULL){
		PANIC("todo");
	}
	else{
		frame->page = NULL;
		return frame;
	}

}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	void *page_addr = pg_round_down(addr); // 페이지 사이즈로 내려서 spt_find 해야 하기 때문 
	uint64_t MAX_STACK = USER_STACK - (1<<20);
	uint64_t addr_v = (uint64_t)addr;
	uint64_t rsp = user ? f->rsp : thread_current()->rsp; 

	if (is_kernel_vaddr(addr)) 
		return false;
	/* physical page는 존재하나, writable하지 않은 address에 write를 시도해서 일어난 fault인 경우, 
       할당하지 않고 즉시 false를 반환한다. */
	if ((!not_present) && write){
    	return false;}

	/* TODO: Validate the fault */
	struct page *page = spt_find_page(spt, page_addr);
	if (page == NULL) {
		if (addr_v > MAX_STACK && addr_v < USER_STACK && addr_v >= rsp -8) {
			vm_stack_growth(page_addr);
			page = spt_find_page(spt, page_addr);
		}
		else { 
			return false ; 
		}
	}
return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
/* VA(가상 주소)에 할당된 페이지를 확보(claim)합니다. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;
	/* TODO: Fill this function */
	
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
/* 지정된 메모리 페이지를 확보하고, 메모리 관리 장치가 이를 관리할 수 있도록 설정한다 */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;
	
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* 할 일: 페이지 테이블 항목을 삽입하여, 해당 페이지의 가상 주소(VA)를 프레임의 물리 주소(PA)에 매핑하라. */
	bool result = pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);

	if(result == false){
		return false;
	}
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void 
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash_spt, page_hash, page_less, NULL); 
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED)
{
    struct hash_iterator i;
    hash_first(&i, &src->hash_spt);
    while (hash_next(&i))
    {
        // src_page 정보
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

        /* 1) type이 uninit이면 */
        if (type == VM_UNINIT)
        { // uninit page 생성 & 초기화
            vm_initializer *init = src_page->uninit.init;
            void *aux = src_page->uninit.aux;
            vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
            continue;
        }

        /* 2) type이 uninit이 아니면 */
        if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
            // init이랑 aux는 Lazy Loading에 필요함
            // 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음
            return false;

        // vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
        if (!vm_claim_page(upage))
            return false;

        // 매핑된 프레임에 내용 로딩
        struct page *dst_page = spt_find_page(dst, upage);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }
    return true;
}
void hash_page_destroy(struct hash_elem *e, void *aux)
{
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);
    free(page);
}

void clear_func (struct hash_elem *elem, void *aux) {
	struct page *page = hash_entry(elem, struct page, hash_elem);
	vm_dealloc_page(page);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_clear(&spt->hash_spt, hash_page_destroy); // 해시 테이블의 모든 요소를 제거
}


unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}