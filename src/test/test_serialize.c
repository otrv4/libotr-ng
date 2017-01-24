#include "../serialize.h"
#include "../deserialize.h"

void
test_ser_deser_uint() {
  uint8_t buf[8] = { 0 };
  const uint8_t ser[8] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

  serialize_uint8(buf, 0x12);
  otrv4_assert_cmpmem(buf, ser, 1);
  
  uint8_t uint8_des = 0;
  g_assert_cmpint(deserialize_uint8(&uint8_des, ser), ==, 0);
  g_assert_cmpuint(uint8_des, ==, 0x12);

  memset(buf, 0, sizeof(buf));
  serialize_uint16(buf, 0x1234);
  otrv4_assert_cmpmem(buf, ser, 2);
  
  uint16_t uint16_des = 0;
  g_assert_cmpint(deserialize_uint16(&uint16_des, ser), ==, 0);
  g_assert_cmpuint(uint16_des, ==, 0x1234);

  memset(buf, 0, sizeof(buf));
  serialize_uint32(buf, 0x12345678);
  otrv4_assert_cmpmem(buf, ser, 4);
  
  uint32_t uint32_des = 0;
  g_assert_cmpint(deserialize_uint32(&uint32_des, ser), ==, 0);
  g_assert_cmpuint(uint32_des, ==, 0x12345678);

  memset(buf, 0, sizeof(buf));
  serialize_uint64(buf, 0x123456789ABCDEF0);
  otrv4_assert_cmpmem(buf, ser, 8);
  
  uint64_t uint64_des = 0;
  g_assert_cmpint(deserialize_uint64(&uint64_des, ser), ==, 0);
  g_assert_cmpuint(uint64_des, ==, 0x123456789ABCDEF0);
}
