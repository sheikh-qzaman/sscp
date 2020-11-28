#ifndef __DLL_H__
#define __DLL_H__

#include <assert.h>
#include <stdio.h>
#include <stdint.h>

#define OFFSET(t, f)    ((size_t)(char *)&((t *)0)->f)

typedef struct t_dlnode
{
    struct t_dlnode *p_next;
    struct t_dlnode *p_prev;
#ifdef DLL_CORRUPTION_CHECKS
    struct t_dll    *root;
#endif
} t_dlnode;

typedef struct t_dll
{
    t_dlnode *p_head;
    t_dlnode *p_tail;
    int       count;   // num nodes on this dll
} t_dll;


#define DLL_INIT(p_dll)        (p_dll)->p_head = (p_dll)->p_tail = NULL;  \
                               (p_dll)->count = 0;

#define DL_NODE_INIT(p_node)   (p_node)->p_prev = (p_node)->p_next = NULL;

#define DLL_FIRST_NODE(p_dll)  (p_dll)->p_head
#define DLL_LAST_NODE(p_dll)   (p_dll)->p_tail
#define DLL_NEXT_NODE(p_node)   (p_node)->p_next
#define DLL_PREV_NODE(p_node)   (p_node)->p_prev

#define DLL_FIRST(struct_foo, field, p_dll)                                  \
({                                                                           \
    struct_foo *pX;                                                          \
                                                                             \
    if ((p_dll)->p_head)                                                     \
        pX = (struct_foo *)((uint8_t *)                                      \
                            (p_dll)->p_head - OFFSET(struct_foo, field));    \
    else                                                                     \
        pX = NULL;                                                           \
    pX;                                                                      \
})
    
#define DLL_LAST(struct_foo, field, p_dll)                                   \
({                                                                           \
    struct_foo *pX;                                                          \
                                                                             \
    if ((p_dll)->p_tail)                                                     \
        pX = (struct_foo *)((uint8_t *)                                      \
                            (p_dll)->p_tail - OFFSET(struct_foo, field));    \
    else                                                                     \
        pX = NULL;                                                           \
    pX;                                                                      \
})

#define DLL_COUNT(p_dll)     (p_dll)->count

#define DLL_NEXT(struct_foo, field, app_node)                                 \
({                                                                           \
    struct_foo *pX;                                                          \
    t_dlnode *p_dlnode;                                                      \
                                                                             \
    p_dlnode = &(app_node)->field;                                           \
    if ((p_dlnode)->p_next)                                                  \
        pX = (struct_foo *)((uint8_t *)                                      \
                            (p_dlnode)->p_next - OFFSET(struct_foo, field));  \
    else                                                                     \
        pX = NULL;                                                           \
    pX;                                                                      \
})


#define DLL_PREV(struct_foo, field, app_node)                                \
({                                                                           \
    struct_foo *pX;                                                          \
    t_dlnode *p_dlnode;                                                      \
                                                                             \
    p_dlnode = &(app_node)->field;                                           \
    if ((p_dlnode)->p_prev)                                                  \
        pX = (struct_foo *)((uint8_t *)                                      \
                            (p_dlnode)->p_prev - OFFSET(struct_foo, field)); \
    else                                                                     \
        pX = NULL;                                                           \
    pX;                                                                      \
})


/* DLL_ADD: Add p_dlnode to the tail of p_dll */
static inline void DLL_ADD(t_dll *p_dll, t_dlnode *p_newnode)
{
    assert(p_newnode->p_next == NULL && p_newnode->p_prev == NULL);

#ifdef DLL_CORRUPTION_CHECKS
    p_newnode->root = p_dll;
#endif

    if (p_dll->p_tail)
    {
        assert(p_dll->count > 0);

        p_dll->p_tail->p_next = p_newnode;
        p_newnode->p_prev     = p_dll->p_tail;
        p_dll->p_tail         = p_newnode;
    }
    else
    {
        assert(p_dll->count == 0);

        p_dll->p_head = p_dll->p_tail = p_newnode;
        p_newnode->p_prev = NULL;
    }

    p_dll->count++;
    p_newnode->p_next = NULL;
}


/* DLL_ADD_NOCOUNT: Add p_dlnode to the tail of p_dll, caller needs to update DLL_COUNT  */
static inline void DLL_ADD_NOCOUNT(t_dll *p_dll, t_dlnode *p_newnode)
{
    assert(p_newnode->p_next == NULL && p_newnode->p_prev == NULL);

#ifdef DLL_CORRUPTION_CHECKS
    p_newnode->root = p_dll;
#endif

    if (p_dll->p_tail)
    {
        assert(p_dll->count > 0);

        p_dll->p_tail->p_next = p_newnode;
        p_newnode->p_prev     = p_dll->p_tail;
        p_dll->p_tail         = p_newnode;
    }
    else
    {
        assert(p_dll->count == 0);

        p_dll->p_head = p_dll->p_tail = p_newnode;
        p_newnode->p_prev = NULL;
    }

    p_newnode->p_next = NULL;
}

/* DLL_INSERT: Insert p_newnode AFTER p_node. If p_node is null, 
  * insert p_newnode at the head
  */
static inline void DLL_INSERT(t_dll *p_dll, t_dlnode *p_node, 
                                      t_dlnode *p_newnode)
{
    assert(p_newnode->p_next == NULL && p_newnode->p_prev == NULL);

#ifdef DLL_CORRUPTION_CHECKS
    p_newnode->root = p_dll;
#endif

    if (p_node)
    {
        p_newnode->p_next    = p_node->p_next;
        if (p_node->p_next)
            p_node->p_next->p_prev = p_newnode;
        else
            p_dll->p_tail = p_newnode;

        p_node->p_next       = p_newnode;

        p_newnode->p_prev    = p_node;
    }
    else
    {
        p_newnode->p_next    = p_dll->p_head;
        if (p_dll->p_head)
            p_dll->p_head->p_prev = p_newnode;

        p_newnode->p_prev = NULL;

        p_dll->p_head        = p_newnode;
    }
    
    if (p_dll->p_tail == p_node)
        p_dll->p_tail = p_newnode;

    p_dll->count++;
}

static inline void DLL_INSERT_BEFORE(t_dll *p_dll, t_dlnode *p_node,
                       t_dlnode *p_newnode)
{
    assert(p_newnode->p_next == NULL && p_newnode->p_prev == NULL);

#ifdef DLL_CORRUPTION_CHECKS
    p_newnode->root = p_dll;
#endif

    if (p_node)
    {
        p_newnode->p_prev    = p_node->p_prev;
        if (p_node->p_prev)
            p_node->p_prev->p_next = p_newnode;
        else
            p_dll->p_head = p_newnode;

        p_node->p_prev       = p_newnode;

        p_newnode->p_next    = p_node;
    }
    else
    {
        p_newnode->p_prev    = p_dll->p_tail;
        if (p_dll->p_tail)
            p_dll->p_tail->p_next = p_newnode;

        p_newnode->p_next = NULL;

        p_dll->p_tail        = p_newnode;
    }
    
    if (p_dll->p_head == p_node)
        p_dll->p_head = p_newnode;

    p_dll->count++;
}

static inline void DLL_REMOVE(t_dll *p_dll, t_dlnode *p_delnode)
{

#ifdef DLL_CORRUPTION_CHECKS
    assert(p_delnode->root == p_dll);
#endif

    if (p_delnode->p_prev)
        p_delnode->p_prev->p_next = p_delnode->p_next;
    else
        p_dll->p_head = p_delnode->p_next;

    if (p_delnode->p_next)
        p_delnode->p_next->p_prev = p_delnode->p_prev;
    else
        p_dll->p_tail = p_delnode->p_prev;

    assert(p_dll->count > 0);
    p_dll->count--;

    p_delnode->p_prev = p_delnode->p_next = NULL;
  
}
/* Vanilla DLL add / del macros. When Head tail usage is not required */
#define DLL_REMOVEN(p_dll, cnt) \
    do { \
        t_dlnode *p; \
        p = p_dll->p_head; \
        p_dll->count -= cnt; \
        while (cnt) {  \
            p = p->p_next; \
            cnt--;\
        } \
        p_dll->p_head = p->p_next; \
        p->p_next->p_prev = NULL; \
    }while (0)

#define DLL_ADD_NEXT(curr, new) \
    do { \
        new->p_next = curr->p_next; \
        new->p_prev = curr; \
        if (curr->p_next) \
            curr->p_next->p_prev = new; \
        curr->p_next = new; \
    } while (0)

#define DLL_DEL_CURR(curr) \
    do { \
        curr->p_prev->p_next = curr->p_next; \
        if (curr->p_next) \
            curr->p_next->p_prev = curr->p_prev; \
        curr->p_prev = curr->p_next = NULL; \
    }while (0)


static inline void DLL_MOVE_N_NODES(t_dll * src, t_dll *dst, int n)
{
    t_dlnode *p, *t;
    int count = ((src->count > n) ? n : src->count);
    if (0 == count) {
        return;
    }
    p = src->p_head;
    dst->count += count; 
    src->count -= count;
    while (--count) {
       p = p->p_next;
    }
    if (dst->p_tail == NULL) {
        dst->p_tail = p;
        dst->p_head = src->p_head;
        src->p_head = p->p_next;
        p->p_next = NULL; 
    } else if (dst->p_head !=NULL) {
        t = dst->p_head;
        dst->p_head = src->p_head;
        src->p_head = p->p_next;
        p->p_next = t;
        t->p_prev = p;
    }
    if (src->p_head)
        src->p_head->p_prev = NULL;
    else
	src->p_tail = NULL;
}

static inline void
DLL_MERGE(t_dll * src, t_dll *dst)
{
    if (dst->p_tail) {
        assert(dst->count != 0);
        dst->p_tail->p_next = src->p_head;
        src->p_head->p_prev = dst->p_tail;
    } else {
        assert(dst->count == 0);
        dst->p_head = src->p_head;
    }
    dst->p_tail = src->p_tail;
    dst->count += src->count;
    src->p_head = src->p_tail = NULL;
    src->count = 0;
}

static inline void
DLL_HEAD_MERGE(t_dll *src, t_dll *dst)
{
    t_dlnode *h = dst->p_head;
    dst->p_head = src->p_head;
    if (h) {
        src->p_tail->p_next = h;
        h->p_prev   = src->p_tail;
    } else {
        dst->p_tail = src->p_tail;
    }
    dst->count  += src->count;
    src->p_head = src->p_tail = NULL;
    src->count = 0;
}

#endif // __DLL_H__
