/*
 * def.h
 * Copyright (C) 2006 - 2012 Addy Yeow Chin Heng <ayeowch@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef _DEF_H_
#define _DEF_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <poll.h>
#include <ifaddrs.h>
#define _NET_IF_ARP_H_ /* OpenBSD's if.h takes in if_arp.h */
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#ifdef __BSD_VISIBLE /* Linux does not have net/if_dl.h */
#include <net/if_dl.h>
#endif
#include <pcap.h>

struct pcap_timeval {
    bpf_int32 tv_sec;       /* seconds */
    bpf_int32 tv_usec;      /* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts; /* time stamp */
    bpf_u_int32 caplen;     /* length of portion present */
    bpf_u_int32 len;        /* length this packet (off wire) */
};

#define BITTWIST_VERSION    "2.0"
#define BITTWISTE_VERSION   BITTWIST_VERSION

#define ETHER_ADDR_LEN      6           /* Ethernet address length */
#define ETHER_HDR_LEN       14          /* Ethernet header length */
#define ETHER_MAX_LEN       1514        /* maximum frame length, excluding CRC */
#define ARP_HDR_LEN         28          /* Ethernet ARP header length */
#define IP_ADDR_LEN         4           /* IP address length */
#define IP_HDR_LEN          20          /* default IP header length */
#define ICMP_HDR_LEN        4           /* ICMP header length */
#define TCP_HDR_LEN         20          /* default TCP header length */
#define UDP_HDR_LEN         8           /* UDP header length */

#define ETHERTYPE_IP        0x0800      /* IP protocol */
#define ETHERTYPE_ARP       0x0806      /* address resolution protocol */

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP        1           /* internet control message protocol */
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP         6           /* transmission control protocol */
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP         17          /* user datagram protocol */
#endif

/* bittwist */
#define LINERATE_MIN        1           /* Mbps */
#define LINERATE_MAX        10000       /* Mbps */
#define SPEED_MIN           0.000001    /* minimum positive value for speed (interval multiplier) */
#define SLEEP_MAX           2146        /* maximum interval in seconds */
#define PKT_PAD             0x00        /* packet padding */

/* bittwiste */
#define PAYLOAD_MAX         1500        /* maximum payload in bytes */
#define ETH                 1           /* supported header specification (dummy values) */
#define ARP                 2
#define IP                  3
#define ICMP                4
#define TCP                 5
#define UDP                 6
#define IP_FO_MAX           7770        /* maximum IP fragment offset (number of 64-bit segments) */

#define PCAP_HDR_LEN        16          /* pcap generic header length */
#define PCAP_MAGIC          0xa1b2c3d4  /* pcap magic number */

#ifndef TIMEVAL_TO_TIMESPEC
#define TIMEVAL_TO_TIMESPEC(tv, ts) {       \
    (ts)->tv_sec = (tv)->tv_sec;            \
    (ts)->tv_nsec = (tv)->tv_usec * 1000;   \
}
#endif

#define ROUND(f) (f >= 0 ? (long)(f + 0.5) : (long)(f - 0.5))

typedef u_int32_t tcp_seq;

struct packet_config
{
    char src_ip[36];
    char dst_mac[18];
    char dst_ip[36];
    uint16_t dst_port;
};

struct resolved_packet_config
{
    uint32_t src_ip;
    unsigned char dst_mac[12];
    uint32_t dst_ip;
    uint16_t dst_port;
};

#endif  /* !_DEF_H_ */
