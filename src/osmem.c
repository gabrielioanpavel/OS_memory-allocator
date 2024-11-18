// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <sys/mman.h>

#include "osmem.h"
#include "block_meta.h"
#include "printf.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

#define MMAP_THRESHOLD (128 * 1024)
#define CALLOC_THRESHOLD (4 * 1024)

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

#ifndef METADATA_SIZE
#define METADATA_SIZE (ALIGN(sizeof(struct block_meta)))
#endif

#define STATUS_SENTINEL 3

struct block_meta list_head;
int preallocated;

size_t min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

struct block_meta *preallocation(void)
{
	list_head.next = &list_head;
	list_head.prev = &list_head;
	list_head.size = 0;
	list_head.status = STATUS_SENTINEL;

	struct block_meta *new_node;

	new_node = (struct block_meta *) sbrk(MMAP_THRESHOLD);
	DIE(new_node == (void *) -1, "sbrk() failure.");

	new_node->status = STATUS_FREE;
	new_node->size = MMAP_THRESHOLD - METADATA_SIZE;

	list_head.next = new_node;
	list_head.prev = new_node;
	new_node->next = &list_head;
	new_node->prev = &list_head;

	return new_node;
}

struct block_meta *find_best_block(size_t size)
{
	struct block_meta *current = list_head.next, *best = NULL;
	size_t best_size = SIZE_MAX;

	while (current != &list_head) {
		if (current->status == STATUS_FREE && current->size >= size && current->size < best_size) {
			best = current;
			best_size = current->size;
		}

		current = current->next;
	}

	return best;
}

struct block_meta *split_block(struct block_meta *node, size_t new_size)
{
	if (node->size - new_size >= METADATA_SIZE + 8) {
		size_t size_after_split = node->size - new_size;
		struct block_meta *new_node = (struct block_meta *) ((char *) node + new_size + METADATA_SIZE);

		node->size = new_size;

		new_node->size = size_after_split - METADATA_SIZE;
		new_node->status = STATUS_FREE;

		new_node->next = node->next;
		new_node->prev = node;
		node->next->prev = new_node;
		node->next = new_node;

		return node;
	}

	return node;
}

struct block_meta *add_new_node(size_t size, size_t threshold)
{
	struct block_meta *new_node;

	if (preallocated == 0 && size + METADATA_SIZE < threshold)
		return split_block(preallocation(), size);

	if (size + METADATA_SIZE < threshold) {
		new_node = (struct block_meta *) sbrk(METADATA_SIZE + size);
		DIE(new_node == (void *) -1, "sbrk() failure.");

		new_node->status = STATUS_ALLOC;
	} else {
		new_node = (struct block_meta *) mmap(NULL, METADATA_SIZE + size, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(new_node == MAP_FAILED, "mmap() failure.");

		new_node->status = STATUS_MAPPED;
		new_node->size = size;

		return new_node;
	}

	new_node->size = size;

	list_head.prev->next = new_node;
	new_node->prev = list_head.prev;
	new_node->next = &list_head;
	list_head.prev = new_node;

	return new_node;
}

void coalesce(struct block_meta *node)
{
	// Special case: previous node is head:
	if (node->prev == &list_head && node->next->status == STATUS_FREE) {
		node->size += node->next->size + METADATA_SIZE;

		node->next->next->prev = node;
		node->next = node->next->next;

		return;
	}

	int freed_left = 0;
	struct block_meta *cursor = node->prev;

	if (cursor->status == STATUS_FREE) {
		cursor->size += node->size + METADATA_SIZE;

		cursor->next = node->next;
		node->next->prev = cursor;

		freed_left = 1;
	}
	if (freed_left == 0)
		cursor = cursor->next;

	if (cursor->next->status == STATUS_FREE && cursor->status == STATUS_FREE) {
		cursor->size += cursor->next->size + METADATA_SIZE;

		cursor->next = cursor->next->next;
		cursor->next->prev = cursor;
	}
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */

	if (size <= 0)
		return NULL;

	size = ALIGN(size);
	struct block_meta *node = NULL;

	if (preallocated == 0 && size < MMAP_THRESHOLD) {
		preallocated = 1;
		node = split_block(preallocation(), size);
		node->status = STATUS_ALLOC;
	} else {
		if (size + METADATA_SIZE >= MMAP_THRESHOLD) {
			node = add_new_node(size, MMAP_THRESHOLD);
		} else {
			struct block_meta *req = find_best_block(size);

			if (req == NULL) {
				if (list_head.prev->status == STATUS_FREE) {
					size_t extend_size = ALIGN(size - list_head.prev->size);

					DIE(sbrk(extend_size) == (void *) -1, "sbrk() failure.");

					list_head.prev->size += extend_size;
					node = list_head.prev;

					node->status = STATUS_ALLOC;
				} else {
					node = add_new_node(size, MMAP_THRESHOLD);
				}
			} else {
				node = split_block(req, size);
				node->status = STATUS_ALLOC;
			}
		}
	}

	return (node + 1);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */

	if (ptr == NULL)
		return;

	struct block_meta *node = (struct block_meta *) ((char *) ptr - METADATA_SIZE);

	if (node->status == STATUS_MAPPED) {
		DIE(munmap(node, node->size + METADATA_SIZE) == -1, "munmap().");
		return;
	}

	node->status = STATUS_FREE;

	coalesce(node);
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */

	if (nmemb == 0 || size == 0)
		return NULL;

	size_t total_size = ALIGN(nmemb*size);
	struct block_meta *node = NULL;

	if (preallocated == 0 && total_size < CALLOC_THRESHOLD - METADATA_SIZE) {
		preallocated = 1;
		node = split_block(preallocation(), total_size);
		node->status = STATUS_ALLOC;
	} else {
		if (total_size + METADATA_SIZE >= CALLOC_THRESHOLD) {
			node = add_new_node(total_size, CALLOC_THRESHOLD);
		} else {
			struct block_meta *req = find_best_block(total_size);

			if (req == NULL) {
				if (list_head.prev->status == STATUS_FREE) {
					size_t extend_size = ALIGN(total_size - list_head.prev->size);

					DIE(sbrk(extend_size) == (void *) -1, "sbrk().");

					list_head.prev->size += extend_size;
					node = list_head.prev;

					node->status = STATUS_ALLOC;
				} else {
					node = add_new_node(total_size, CALLOC_THRESHOLD);
				}
			} else {
				node = split_block(req, total_size);
				node->status = STATUS_ALLOC;
			}
		}
	}

	void *ptr = (void *) (node + 1);

	memset(ptr, 0, total_size);

	return (node + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */

	if (ptr == NULL)
		return os_malloc(size);

	int flag = 0; // Made this because the linter was not happy with my code

	size = ALIGN(size);
	struct block_meta *node = (struct block_meta *) ((char *) ptr - METADATA_SIZE), *new_node, *req;

	if (node->status == STATUS_FREE)
		return NULL;

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	if (node->status == STATUS_MAPPED) {
		if (preallocated && size < MMAP_THRESHOLD) {
			req = find_best_block(size);
			if (req) {
				memcpy((void *) (req + 1), ptr, min(node->size, size));
				new_node = split_block(req, size);
				new_node->status = STATUS_ALLOC;
				os_free(ptr);
			} else {
				new_node = add_new_node(size, MMAP_THRESHOLD);
				memcpy((void *) (new_node + 1), ptr, min(node->size, new_node->size));
				os_free(ptr);
			}
		} else {
			new_node = add_new_node(size, MMAP_THRESHOLD);
			memcpy((void *) (new_node + 1), ptr, min(node->size, new_node->size));
			os_free(ptr);
		}
	} else {
		if (node->size >= size) {
			new_node = split_block(node, size);
			coalesce(node->next);
		} else if (node->size + node->next->size + METADATA_SIZE >= size && node->next->status == STATUS_FREE) {
			node->size += node->next->size + METADATA_SIZE;
			node->next->next->prev = node;
			node->next = node->next->next;

			new_node = split_block(node, size);
			coalesce(node->next);
			flag = 1;
		} else {
			if (node == list_head.prev) {
				size_t extend_size = ALIGN(size - list_head.prev->size);

				DIE(sbrk(extend_size) == (void *) -1, "sbrk() failure.");

				list_head.prev->size += extend_size;
				new_node = list_head.prev;
			} else {
				req = find_best_block(size);
				if (req == NULL) {
					if (size >= MMAP_THRESHOLD) {
						new_node = add_new_node(size, MMAP_THRESHOLD);
						memcpy((void *) (new_node + 1), ptr, min(new_node->size, node->size));
						os_free(ptr);
					} else if (list_head.prev->status == STATUS_FREE) {
						size_t extend_size = ALIGN(size - list_head.prev->size);

						DIE(sbrk(extend_size) == (void *) -1, "sbrk() failure.");

						list_head.prev->size += extend_size;
						new_node = list_head.prev;

						new_node->status = STATUS_ALLOC;

						memcpy((void *) (new_node + 1), ptr, node->size);
					} else {
						new_node = (struct block_meta *) ((char *) os_malloc(size) - METADATA_SIZE);
						memcpy((void *) (new_node + 1), ptr, node->size);
						os_free(ptr);
					}
				} else {
					memcpy((void *) (req + 1), ptr, node->size);
					new_node = split_block(req, size);
					new_node->status = STATUS_ALLOC;
					coalesce(node->next);
					os_free(ptr);
				}
			}
		}
	}

	if (flag)
		return ptr;

	return (new_node + 1);
}
