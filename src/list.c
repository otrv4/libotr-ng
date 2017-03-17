#include <stdlib.h>

#include "list.h"

list_element_t *list_new()
{
	list_element_t *n = malloc(sizeof(list_element_t));
	if (!n)
		return n;

	n->data = NULL;
	n->next = NULL;

	return n;
}

void list_free_full(list_element_t * head)
{
	list_element_t *current = head;
	while (current) {
		list_element_t *next = current->next;
		free(current->data);
		free(current);
		current = next;
	}
}

void list_free_all(list_element_t * head)
{
	list_element_t *current = head;
	while (current) {
		list_element_t *next = current->next;
		free(current);
		current = next;
	}
}

list_element_t *list_add(void *data, list_element_t * head)
{
	list_element_t *n = list_new();
	if (!n)
		return NULL;

	n->data = data;

	list_element_t *last = list_get_last(head);
	if (!last)
		return n;

	last->next = n;
	return head;
}

list_element_t *list_get_last(list_element_t * head)
{
	if (!head)
		return NULL;

	list_element_t *cursor = head;
	while (cursor->next)
		cursor = cursor->next;

	return cursor;
}
