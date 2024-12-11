#include "coco.h"
#include "log.h"
#include "unity.h"

u64 sum = 0;

void addup(void* arg) {
  u64 x = *(u64*)arg;
  sum += x;
}

void test_coco_pool(void) {
  Allocator al = allocator_libc();
  CocoPool pool;
  CHECK0(CocoPool_init(&pool, 8, 1024 * 32, al));

  sum = 0;
  u64 nums[64];

  for (usize i = 0; i < ARRAY_LEN(nums); ++i) {
    nums[i] = i;
    CHECK0(CocoPool_go(&pool, addup, &nums[i]));
  }

  CHECK(sum == 32 * 63, "%" PRIu64, sum);

  CocoPool_deinit(&pool);
}

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_coco_pool);
  return UNITY_END();
}
