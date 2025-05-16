#ifndef THREAD_MMU_H
#define THREAD_MMU_H

#include <stdbool.h>
#include <stdint.h>
#include "threads/pte.h"

typedef bool pte_for_each_func (uint64_t *pte, void *va, void *aux);
// PML4 : Page-Map-Level-4
uint64_t *pml4e_walk (uint64_t *pml4, const uint64_t va, int create);
uint64_t *pml4_create (void);
bool pml4_for_each (uint64_t *, pte_for_each_func *, void *); //각 pml4가 유효한 entry를 가지고 있는지 검사하며, 검사를 위해 보조값 aux를 받는 함수 func를 추가적으로 활용 / false를 리턴하면, 반복을 멈추고 false를 리턴
void pml4_destroy (uint64_t *pml4);
void pml4_activate (uint64_t *pml4);
void *pml4_get_page (uint64_t *pml4, const void *upage);
bool pml4_set_page (uint64_t *pml4, void *upage, void *kpage, bool rw);
void pml4_clear_page (uint64_t *pml4, void *upage);
bool pml4_is_dirty (uint64_t *pml4, const void *upage);
void pml4_set_dirty (uint64_t *pml4, const void *upage, bool dirty);
bool pml4_is_accessed (uint64_t *pml4, const void *upage);
void pml4_set_accessed (uint64_t *pml4, const void *upage, bool accessed);

#define is_writable(pte) (*(pte) & PTE_W)		//PTE가 가리키는 가상주소가 작성 가능한 지(wriatable) 아닌 지 확인
#define is_user_pte(pte) (*(pte) & PTE_U)		//페이지 테이블 엔트리(PTE)의 주인이 유저인지 커널인지 확인
#define is_kern_pte(pte) (!is_user_pte (pte))	//user pte 라면 유저/커널, kernel pte 라면 커널 only

#define pte_get_paddr(pte) (pg_round_down(*(pte)))

/* Segment descriptors for x86-64. */
struct desc_ptr {
	uint16_t size;
	uint64_t address;
} __attribute__((packed));

#endif /* thread/mm.h */
