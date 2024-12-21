#ifndef SIGNUM_H
#define SIGNUM_H

#include <stddef.h>

/* an injective function that returns an array index
 * corresponding to the given signal number,
 * which must be a valid non-realtime signal number
 * or zero. */
__attribute__((const))
static inline size_t sigindex(int signum) {
    return (size_t) signum;
}

/* max index returned by sigindex + 1 */
#define MAXSIGIDX 32

/* number of realtime signals that can be handled by yash */
#define RTSIZE 0

#endif
