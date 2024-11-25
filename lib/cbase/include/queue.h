#pragma once

typedef struct Node {
  struct Node* next;
} Node;

typedef struct {
  Node* head;
  Node* tail;
} Queue;

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
