#ifndef __LIB_KERNEL_HASH_H
#define __LIB_KERNEL_HASH_H

/* Hash table.
 *
 * This data structure is thoroughly documented in the Tour of
 * Pintos for Project 3.
 *
 * This is a standard hash table with chaining.  To locate an
 * element in the table, we compute a hash function over the
 * element's data and use that as an index into an array of
 * doubly linked lists, then linearly search the list.
 *
 * The chain lists do not use dynamic allocation.  Instead, each
 * structure that can potentially be in a hash must embed a
 * struct hash_elem member.  All of the hash functions operate on
 * these `struct hash_elem's.  The hash_entry macro allows
 * conversion from a struct hash_elem back to a structure object
 * that contains it.  This is the same technique used in the
 * linked list implementation.  Refer to lib/kernel/list.h for a
 * detailed explanation. */
/* 해시 테이블.
 *
 * 이 자료구조에 대해서는 Pintos Project 3의 Tour 문서에 자세히 설명되어 있다.
 *
 * 이 해시 테이블은 체이닝(chaining) 방식의 일반적인 해시 테이블이다.
 * 테이블에서 어떤 요소를 찾을 때는, 그 요소의 데이터에 대해 해시 함수를 계산하고,
 * 그 값을 인덱스로 사용하여 이중 연결 리스트 배열 중 하나를 선택한 뒤,
 * 해당 리스트를 선형 탐색(linear search)한다.
 *
 * 이 체인 리스트들은 동적 할당을 사용하지 않는다.
 * 대신, 해시에 들어갈 수 있는 모든 구조체는 내부에
 * `struct hash_elem` 멤버를 포함해야 한다.
 * 해시 관련 모든 함수들은 이 `struct hash_elem`에 대해 작동한다.
 * `hash_entry` 매크로를 사용하면 `struct hash_elem` 포인터로부터
 * 그것을 포함한 원래 구조체의 포인터로 다시 변환할 수 있다.
 * 이 기법은 연결 리스트 구현에서도 동일하게 사용된다.
 * 자세한 설명은 lib/kernel/list.h 파일을 참고하라.
 */


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "list.h"

/* Hash element. */
struct hash_elem {
	struct list_elem list_elem;
};

/* Converts pointer to hash element HASH_ELEM into a pointer to
 * the structure that HASH_ELEM is embedded inside.  Supply the
 * name of the outer structure STRUCT and the member name MEMBER
 * of the hash element.  See the big comment at the top of the
 * file for an example. */
/* 해시 요소 HASH_ELEM에 대한 포인터를,
 * 그 요소가 포함되어 있는 외부 구조체의 포인터로 변환한다.
 * 이때, 외부 구조체의 이름 STRUCT와,
 * 해시 요소가 구조체 내에 들어있는 멤버 변수 이름 MEMBER를 제공해야 한다.
 * 사용 예시는 이 파일 맨 위의 큰 주석을 참고하라. */
#define hash_entry(HASH_ELEM, STRUCT, MEMBER)                   \
	((STRUCT *) ((uint8_t *) &(HASH_ELEM)->list_elem        \
		- offsetof (STRUCT, MEMBER.list_elem)))

/* Computes and returns the hash value for hash element E, given
 * auxiliary data AUX. */
/* 해시 요소 E에 대해 해시 값을 계산하여 반환한다.
 * 이때, 보조 데이터 AUX를 참고한다. */
typedef uint64_t hash_hash_func (const struct hash_elem *e, void *aux);

/* Compares the value of two hash elements A and B, given
 * auxiliary data AUX.  Returns true if A is less than B, or
 * false if A is greater than or equal to B. */
/* 두 해시 요소 A와 B의 값을 비교한다.
 * 이때, 보조 데이터 AUX를 참고한다.
 * A가 B보다 작으면 true를 반환하고,
 * 그렇지 않으면 (A가 B보다 크거나 같으면) false를 반환한다. */
typedef bool hash_less_func (const struct hash_elem *a,
		const struct hash_elem *b,
		void *aux);

/* Performs some operation on hash element E, given auxiliary
 * data AUX. */
typedef void hash_action_func (struct hash_elem *e, void *aux);

/* Hash table. */
struct hash {
	size_t elem_cnt;            /* Number of elements in table. */
	size_t bucket_cnt;          /* Number of buckets, a power of 2. */
	struct list *buckets;       /* Array of `bucket_cnt' lists. */
	hash_hash_func *hash;       /* Hash function. */
	hash_less_func *less;       /* Comparison function. */
	void *aux;                  /* Auxiliary data for `hash' and `less'. */
};

/* A hash table iterator. */
struct hash_iterator {
	struct hash *hash;          /* The hash table. */
	struct list *bucket;        /* Current bucket. */
	struct hash_elem *elem;     /* Current hash element in current bucket. */
};

/* Basic life cycle. */
bool hash_init (struct hash *, hash_hash_func *, hash_less_func *, void *aux);
void hash_clear (struct hash *, hash_action_func *);
void hash_destroy (struct hash *, hash_action_func *);

/* Search, insertion, deletion. */
struct hash_elem *hash_insert (struct hash *, struct hash_elem *);
struct hash_elem *hash_replace (struct hash *, struct hash_elem *);
struct hash_elem *hash_find (struct hash *, struct hash_elem *);
struct hash_elem *hash_delete (struct hash *, struct hash_elem *);

/* Iteration. */
void hash_apply (struct hash *, hash_action_func *);
void hash_first (struct hash_iterator *, struct hash *);
struct hash_elem *hash_next (struct hash_iterator *);
struct hash_elem *hash_cur (struct hash_iterator *);

/* Information. */
size_t hash_size (struct hash *);
bool hash_empty (struct hash *);

/* Sample hash functions. */
uint64_t hash_bytes (const void *, size_t);
uint64_t hash_string (const char *);
uint64_t hash_int (int);

#endif /* lib/kernel/hash.h */
