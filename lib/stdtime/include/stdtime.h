#pragma once

#include "stdtypes.h"

#define STDTIME_RFC3339_UTC_TIMESTAMP_LEN 21

// All timestamp strings are in RFC3339 format in UTC with only seconds.
// https://datatracker.ietf.org/doc/html/rfc3339
// Example: 2024-12-03T03:03:28Z

void stdtime_rfc3339_utc_format(Bytes ts, i64 epoch_secs);
void stdtime_rfc3339_utc_now(Bytes ts);
int  stdtime_rfc3339_utc_parse(Bytes ts, i64* epoch_secs);
i64  stdtime_now_secs(void);
i64  stdtime_now_ms(void);
i64  stdtime_now_monotonic_secs(void);
i64  stdtime_now_monotonic_ms(void);
