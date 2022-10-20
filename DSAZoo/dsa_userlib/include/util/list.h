/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2015-2019 Intel Corporation. All rights reserved. */

#ifndef _ACCFG_LIST_H_
#define _ACCFG_LIST_H_

#include <ccan/list/list.h>

/**
 * list_add_after - add an entry after the given node in the linked list.
 * @h: the list_head to add the node to
 * @l: the list_node after which to add to
 * @n: the list_node to add to the list.
 *
 * The list_node does not need to be initialized; it will be overwritten.
 * Example:
 *	struct child *child = malloc(sizeof(*child));
 *
 *	child->name = "geoffrey";
 *	list_add_after(&parent->children, &child1->list, &child->list);
 *	parent->num_children++;
 */
#define list_add_after(h, l, n) list_add_after_(h, l, n, LIST_LOC)
static inline void list_add_after_(struct list_head *h,
				   struct list_node *l,
				   struct list_node *n,
				   const char *abortstr)
{
	if (l->next == &h->n) {
		/* l is the last element, this becomes a list_add_tail */
		list_add_tail(h, n);
		return;
	}
	n->next = l->next;
	n->prev = l;
	l->next->prev = n;
	l->next = n;
	(void)list_debug(h, abortstr);
}

#endif /* _ACCFG_LIST_H_ */
