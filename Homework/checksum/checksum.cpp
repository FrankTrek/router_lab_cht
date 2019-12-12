#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
    uint32_t old_sum = packet[10] << 8 | packet[11];
    packet[10] = packet[11] = 0;
    len = (packet[0] & 0x0F) << 2;
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i += 2)
        sum += packet[i+1] | packet[i] << 8;
    while (sum >> 16 > 0)
        sum = (sum >> 16) + (sum & 0xFFFF);
    sum = ~sum & 0xFFFF;
    packet[10] = sum >> 8;
    packet[11] = sum & 0xff;
    return sum == old_sum;
}
