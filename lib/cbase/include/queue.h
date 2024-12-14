#pragma once

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
  if (q->tail) {
    q->tail->next = x;
  } else {
    q->head = x;
    q->tail = x;
  }
}

static inline Node* q_deq(Queue* q) {
  if (q->head == 0)
    return 0;

  Node* x = q->head;
  if (q->head == q->tail) {
    q->head = 0;
    q->tail = 0;
    return x;
  }

  q->head = x->next;
  return x;
}

// Drain the queue, running code for each node.
// code can re-enqueue, the drain will only run through the original tail.
#define q_drain(q, nvar, code)                                                 \
  do {                                                                         \
    Node* __tail = (q)->tail;                                                  \
    while (((nvar) = q_deq((q)))) {                                            \
      code;                                                                    \
      if ((nvar) == __tail)                                                    \
        break;                                                                 \
    }                                                                          \
  } while (0)
