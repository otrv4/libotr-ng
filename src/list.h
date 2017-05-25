#ifndef LIST_H
#define LIST_H

typedef struct _list_element {
	void *data;
	struct _list_element *next;
} list_element_t;

list_element_t *list_new();

void list_free_full(list_element_t * head);

void list_free_all(list_element_t * head);

list_element_t *list_add(void *data, list_element_t * head);

list_element_t *list_get_last(list_element_t * head);

list_element_t *list_get_by_value(const void *wanted, list_element_t * head);

list_element_t *list_remove_element(const list_element_t * wanted,
				    list_element_t * head);

size_t list_len(list_element_t * head);

#endif
