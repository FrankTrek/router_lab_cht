#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define CYAN printf("\e[36m")
#define GREEN printf("\e[32m")
#define CLOSE_COLOR printf("\e[0m")

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern RoutingTableEntry router_table[100]; // 路由表
extern uint32_t router_table_len;  // 路由表长度
extern uint32_t masks[33];  // len转换成mask的数组

// 组播的ip地址
uint32_t multicast_ip_addr = 0x090000e0;
// 组播的mac地址
macaddr_t multicast_mac_addr = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};
uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                     0x0103000a};

void print_route_table() {
  CYAN; printf("router_table:");
  for (int i = 0; i < router_table_len; i++) {
    RoutingTableEntry& rte = router_table[i];
    uint32_t addr = rte.addr;
    uint32_t nthp = rte.nexthop;
    CYAN;  printf("addr: ");
    GREEN; printf("%u.%u.%u.%u ", addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff);
    CYAN;  printf("len: ");
    GREEN; printf("%2u ", rte.len);
    CYAN;  printf("if: ");
    GREEN; printf("%u ", rte.len);
    CYAN;  printf("nexthop: ");
    GREEN; printf("%u.%u.%u.%u ", nthp & 0xff, (nthp >> 8) & 0xff, (nthp >> 16) & 0xff, (nthp >> 24) & 0xff);
    CYAN;  printf("metric: ");
    GREEN; printf("%u\n", htonl(rte.metric));
  }
  CLOSE_COLOR;
}

int query_router_entry(uint32_t addr, uint32_t len) {
  for (int i = 0; i < router_table_len; i++) {
    if (router_table[i].addr == addr && router_table[i].len == len)
      return i;
  }
  return -1;
}

// 初始化ip和udp头，都是常数字段
void init_ip_udp_head() {
  output[0] = 0x45;
  output[1] = 0x0;
  output[4] = output[5] = output[6] = output[7] = 0;
  output[8] = 1;    // ttl设置为1
  output[9] = 0x11; // udp协议为17，即0x11
  output[10] = output[11] = 0;

  output[20] = 0x02, output[21] = 0x08;  // udp src port 520
  output[22] = 0x02, output[23] = 0x08;  // udp dst port 520
  output[26] = output[27] = 0;
}

// mask转换成len的函数
uint32_t mask_to_len(uint32_t mask) {
  uint32_t len = 32;
  while(!(mask & 1) && len > 0) { len--; mask >>= 1; }
  return len;
}

// 设置ip和udp的地址及长度，并计算校验和
void set_ip_udp_head(uint32_t length, uint32_t src, uint32_t dst) {
  output[2] = (length >> 8) & 0xff;
  output[3] = length & 0xff;
  *((uint32_t*) (output + 12)) = src;
  *((uint32_t*) (output + 16)) = dst;
  validateIPChecksum(output, length);

  length -= 20;
  output[24] = (length >> 8) & 0xff;
  output[25] = length & 0xff;
}

// RoutingTableEntry转换成RipEntry
void set_rip_entry(RipEntry& t, RoutingTableEntry& s) {
  t.addr = s.addr;
  t.mask = ntohl(masks[s.len]); // 注意小端序转换成大端序
  t.nexthop = s.nexthop;
  t.metric = s.metric;
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
        .metric = ntohl(1) // !!!metric应该初始化 1
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      init_ip_udp_head();
      // 对每个端口发送不同的rip response报文（水平分割）
      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        uint32_t cnt = 0; // rip表项计数
        RipPacket rip;    // rip包
        rip.command = 2;  // response报文的command为2
        // 组装rip packet
        for (int j = 0; j < router_table_len; j++) {
          // 只发送不同端口的表项，即端口a的表项不会发回给端口a
          if (router_table[j].if_index != i)
            set_rip_entry(rip.entries[cnt++], router_table[j]);
        }
        rip.numEntries = cnt;             // 填入表项数量
        assemble(&rip, output + 28);      // 组装rip报文
        uint32_t length = 32 + cnt * 20;  // ip包总长度
        set_ip_udp_head(length, addrs[i], multicast_ip_addr);
        HAL_SendIPPacket(i, output, length, multicast_mac_addr);
      }
      printf("30s Timer\n");
      print_route_table();
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = *((uint32_t*) (packet + 12));  // ip源地址
    dst_addr = *((uint32_t*) (packet + 16));  // ip目的地址

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // 如果是rip组播地址，也设置成true
    dst_is_me |= (memcmp(&dst_addr, &multicast_ip_addr, sizeof(in_addr_t)) == 0);

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab

          // 和30s计时器中的response组装逻辑基本相同
          // 区别在于这次只给src_addr发，不需要每个端口都发送
          init_ip_udp_head();
          uint32_t cnt = 0;
          RipPacket resp;
          resp.command = 2;
          for (int j = 0; j < router_table_len; j++) {
            if (router_table[j].if_index != if_index)
              set_rip_entry(resp.entries[cnt++], router_table[j]);
          }
          resp.numEntries = cnt;
          // assemble
          assemble(&resp, output + 28);
          uint32_t length = 32 + cnt * 20;
          set_ip_udp_head(length, addrs[if_index], src_addr);
          HAL_SendIPPacket(if_index, output, length, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1

          // 对收到的每一个rip表项操作
          for (int i = 0; i < rip.numEntries; i++) {
            RipEntry& r_entry = rip.entries[i];
            int metric = ntohl(r_entry.metric) + 1; // 新的metrix为收到的metrix+1
            uint32_t len = mask_to_len(ntohl(r_entry.mask));
            int idx = query_router_entry(r_entry.addr, len);
            if (idx >= 0) {  // 若查找到则为表项序号，否则为-1
              RoutingTableEntry& rte = router_table[idx]; // 查找到的表项的引用
              if (rte.if_index == if_index) {
                if (rte.nexthop == 0)
                  continue; // 如果是直连路由则直接跳过
                if (metric > 16) {
                  rte = router_table[--router_table_len]; // 直接操作数组删除表项
                } else {
                  rte.if_index = if_index;
                  rte.metric = ntohl(metric);
                  rte.nexthop = src_addr;
                }
              } else if (metric < ntohl(rte.metric)) {
                rte.if_index = if_index;
                rte.metric = ntohl(metric);
                rte.nexthop = src_addr;
              }
              // 没有查到，且metrix小于16，一定是直接插入新的表项
            } else if (metric <= 16) { // 直接操作数组插入新的表项
              RoutingTableEntry& rte = router_table[router_table_len++];
              rte.addr = r_entry.addr;
              rte.if_index = if_index;
              rte.len = len;
              rte.metric = ntohl(metric);
              rte.nexthop = src_addr;
            }
          }
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // ttl == 0 则直接忽略
          if (output[8] != 0) {
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
