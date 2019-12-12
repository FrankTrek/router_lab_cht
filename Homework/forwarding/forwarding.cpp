#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
    uint32_t old_sum = packet[10] << 8 | packet[11];
    packet[10] = packet[11] = 0;
    len = (packet[0] & 0x0F) << 2;
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i += 2)
        sum += packet[i+1] | packet[i] << 8;
    // 保存一下当前的求和结果，以供增量更新使用
    uint32_t total_sum = sum;
    while (sum >> 16 > 0)
        sum = (sum >> 16) + (sum & 0xffff);
    if ((~sum & 0xffff) != old_sum)
        return false;

    // 增量更新
    packet[8]--;
    total_sum -= 1 << 8;
    sum = total_sum;
    while (sum >> 16 > 0)
        sum = (sum >> 16) + (sum & 0xffff);
    sum = ~sum & 0xffff;

    packet[10] = sum >> 8;
    packet[11] = sum & 0xff;
    return true;
}
