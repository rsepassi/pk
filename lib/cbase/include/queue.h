#pragma once

#include <stdlib.h>

typedef struct Node {
  struct Node* next;
} Node;

typedef struct {
  Node* head;
  Node* tail;
} Queue;

typedef struct Node2 {
  struct Node2* next;
  struct Node2* prev;
} Node2;

typedef struct {
  Node2* head;
  Node2* tail;
} Queue2;

static inline void q_enq(Queue* q, Node* x) {
  x->next = 0;
  if (q->head == 0) {
    q->head = x;
    q->tail = x;
  } else if (q->head == q->tail) {
    q->head->next = x;
    q->tail       = x;
  } else {
    q->tail->next = x;
    q->tail       = x;
  }
}

static inline Node* q_deq(Queue* q) {
  if (q->head == 0)
    return 0;
  else if (q->head == q->tail) {
    Node* x = q->head;
    q->head = 0;
    q->tail = 0;
    return x;
  } else {
    Node* x = q->head;
    q->head = q->head->next;
    return x;
  }
}

static inline size_t q_len(Queue* q) {
  if (q->head == 0)
    return 0;
  if (q->head == q->tail)
    return 1;

  size_t i   = 1;
  Node*  cur = q->head;
  while (cur != q->tail) {
    cur = cur->next;
    ++i;
  }

  return i;
}

// Drain the queue, running code for each node.
// code can re-enqueue, the drain will only run through the original tail.
#define q_drain(q, nvar, code)                                                 \
  do {                                                                         \
    Node* __tail = (q)->tail;                                                  \
    while (((nvar) = q_deq((q)))) {                                            \
      bool __is_tail = ((nvar) == __tail);                                     \
      code;                                                                    \
      if (__is_tail)                                                           \
        break;                                                                 \
    }                                                                          \
  } while (0)

static inline void q2_enq(Queue2* q, Node2* x) {
  x->next = 0;
  x->prev = 0;
  if (q->head == 0) {
    q->head = x;
    q->tail = x;
  } else if (q->head == q->tail) {
    q->head->next = x;
    q->tail       = x;
  } else {
    x->prev       = q->tail;
    q->tail->next = x;
    q->tail       = x;
  }
}

static inline Node2* q2_deq(Queue2* q) {
  if (q->head == 0)
    return 0;
  else if (q->head == q->tail) {
    Node2* x = q->head;
    q->head  = 0;
    q->tail  = 0;
    return x;
  } else {
    Node2* x      = q->head;
    q->head       = q->head->next;
    q->head->prev = 0;
    return x;
  }
}

static inline Node2* q2_pop(Queue2* q) {
  if (q->tail == 0)
    return 0;
  else if (q->head == q->tail) {
    Node2* x = q->tail;
    q->head  = 0;
    q->tail  = 0;
    return x;
  } else {
    Node2* x      = q->tail;
    q->tail       = q->tail->prev;
    q->tail->next = 0;
    return x;
  }
}

static inline size_t q2_len(Queue2* q) {
  if (q->head == 0)
    return 0;
  if (q->head == q->tail)
    return 1;

  size_t i   = 1;
  Node2* cur = q->head;
  while (cur != q->tail) {
    cur = cur->next;
    ++i;
  }

  return i;
}

static inline void q2_del(Queue2* q, Node2* n) {
  if (q->head == n) {
    q2_deq(q);
    return;
  }
  if (q->tail == n) {
    q2_pop(q);
    return;
  }

  if (n->prev)
    n->prev->next = n->next;
  if (n->next)
    n->next->prev = n->prev;
}

// Drain the queue, running code for each node.
// code can re-enqueue, the drain will only run through the original tail.
#define q2_drain(q, nvar, code)                                                \
  do {                                                                         \
    Node2* __tail = (q)->tail;                                                 \
    while (((nvar) = q2_deq((q)))) {                                           \
      bool __is_tail = ((nvar) == __tail);                                     \
      code;                                                                    \
      if (__is_tail)                                                           \
        break;                                                                 \
    }                                                                          \
  } while (0)
