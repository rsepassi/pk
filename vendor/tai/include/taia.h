#ifndef TAIA_H
#define TAIA_H

#include "tai.h"

struct taia {
  struct tai sec;
  unsigned long nano; /* 0...999999999 */
  unsigned long atto; /* 0...999999999 */
} ;

extern void taia_tai();

extern void taia_now(struct taia *t);

extern double taia_approx();
extern double taia_frac();

extern void taia_add();
extern void taia_sub();
extern void taia_half();
extern int taia_less();

#define TAIA_PACK 16
extern void taia_pack(char *s, struct taia *t);
extern void taia_unpack();

#define TAIN_PACK 12
extern void tain_pack(char *s, struct taia *t);
extern void tain_unpack();

#define TAIA_FMTFRAC 19
extern unsigned int taia_fmtfrac();

#endif
