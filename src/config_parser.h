#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h> // for ethernet header
#include <netinet/ip.h>       // for ip header
#include <netinet/udp.h>      // for udp header
#include <netinet/tcp.h>
#include <arpa/inet.h> // to avoid warning at inet_ntoa

#include "jsmn.h"

#define SRC_IP_KEY "source_ip"
#define DST_IP_KEY "dest_ip"
#define DST_PORT_KEY "dest_port"
#define DST_MAC_KEY "dest_mac"
#define CONFIG_GROUP_KEY "configs"


int build_mac(const char *mac_addresss, unsigned char *mac_array)
{
    int i = 0;
    unsigned int o0, o1, o2, o3, o4, o5;
    if (sscanf(mac_addresss, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5) != 6)
    {
        fprintf(stderr, "Invalid MAC address: %s\n", mac_addresss);
        return 0;
    }

    mac_array[0] = o0;
    mac_array[1] = o1;
    mac_array[2] = o2;
    mac_array[3] = o3;
    mac_array[4] = o4;
    mac_array[5] = o5;
    return 1;
}

uint32_t build_ip(const char *ip)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    inet_aton(ip, &addr.sin_addr);
    return addr.sin_addr.s_addr;
}

uint16_t build_port(const uint16_t port)
{
    return htons(port);
}

int resolve_packet_configurations(const struct packet_config *config, struct resolved_packet_config *resolved_config)
{

    if (resolved_config == NULL || config == NULL)
    {
        fprintf(stderr, "resolved_config or config is NULL\n");
        return 0;
    }

    memset(resolved_config, 0, sizeof(struct resolved_packet_config));
    if (config->src_ip != NULL)
    {
        resolved_config->src_ip = build_ip(config->src_ip);
    }

    if (config->dst_ip != NULL)
    {
        resolved_config->dst_ip = build_ip(config->dst_ip);
    }

    if (config->dst_mac != NULL)
    {
        if (!build_mac(config->dst_mac, resolved_config->dst_mac))
        {
            fprintf(stderr, "Cannot resolve destination mac address. Give: %s\n", config->dst_mac);
            return 0;
        }
    }

    if (config->dst_port != 0)
    {
        resolved_config->dst_port = build_port(config->dst_port);
    }

    return 1;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0)
    {
        return 0;
    }
    return -1;
}

static int _parse_config(FILE *fd, struct resolved_packet_config **configs);

int parse_config(const char *file_path, struct resolved_packet_config **configs)
{
    int n;
    FILE *fd = fopen(file_path, "r");

    if (fd < 0)
    {
        fprintf(stderr, "%s does not exist\n", file_path);
        return 0;
    }

    n = _parse_config(fd, configs);
    fclose(fd);

    return n;
}

static int _parse_config(FILE *fd, struct resolved_packet_config **configs)
{
    jsmn_parser json_parser;
    int file_length = 0;
    char *file_content = NULL;
    jsmntok_t t[128];
    int r;
    int i;
    int config_count = 0;
    int bytes_read;

    fseek(fd, 0, SEEK_END);
    file_length = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    file_content = (char *)malloc(sizeof(char) * (file_length + 1));
    bytes_read = fread(file_content, sizeof(char), file_length, fd);
    file_content[file_length] = 0;

    printf("bytes_read = %d, file_length = %d\n", bytes_read, file_length);

    jsmn_init(&json_parser);

    r = jsmn_parse(&json_parser, file_content, file_length, t, sizeof(t) / sizeof(t[0]));

    if (r < 0)
    {
        printf("Failed to parse JSON: %d\n", r);
        return 0;
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT)
    {
        printf("Object expected\n");
        return 0;
    }

    printf("r = %d\n", r);

    for (i = 1; i < r; i++)
    {
        if (jsoneq(file_content, &t[i], CONFIG_GROUP_KEY) == 0)
        {
            int j;
            printf("- Groups:\n");
            if (t[i + 1].type != JSMN_ARRAY)
            {
                printf("Unexpected key: %.*s\n", t[i].end - t[i].start,
                       file_content + t[i].start);
            }

            printf("t+1 size: %d\n", t[i + 1].size); // array size

            *configs = (struct resolved_packet_config *)malloc(sizeof(struct resolved_packet_config) * t[i + 1].size);

            int array_index = i + 1;

            for (j = 0; j < t[array_index].size; j++)
            {
                jsmntok_t *g = &t[i + j + 2];
                int k;

                char src_ip[36];
                char dst_ip[36];
                char dst_mac[18];
                int dst_port;

                memset(src_ip, 0, sizeof(char) * 36);
                memset(dst_ip, 0, sizeof(char) * 36);
                memset(dst_mac, 0, sizeof(char) * 18);
                dst_port = 0;

                for (k = 1; k < g->size * 2; k++)
                {
                    if (jsoneq(file_content, &g[k], SRC_IP_KEY) == 0)
                    {
                        /* We may use strndup() to fetch string value */
                        printf("- %s: %.*s\n", SRC_IP_KEY, g[k + 1].end - g[k + 1].start,
                               file_content + g[k + 1].start);

                        strncpy(src_ip, file_content + g[k + 1].start, g[k + 1].end - g[k + 1].start);

                        k++;
                    }
                    else if (jsoneq(file_content, &g[k], DST_IP_KEY) == 0)
                    {
                        /* We may use strndup() to fetch string value */
                        printf("- %s: %.*s\n", DST_IP_KEY, g[k + 1].end - g[k + 1].start,
                               file_content + g[k + 1].start);

                        strncpy(dst_ip, file_content + g[k + 1].start, g[k + 1].end - g[k + 1].start);

                        k++;
                    }
                    else if (jsoneq(file_content, &g[k], DST_MAC_KEY) == 0)
                    {
                        /* We may use strndup() to fetch string value */
                        printf("- %s: %.*s\n", DST_MAC_KEY, g[k + 1].end - g[k + 1].start,
                               file_content + g[k + 1].start);

                        strncpy(dst_mac, file_content + g[k + 1].start, g[k + 1].end - g[k + 1].start);

                        k++;
                    }
                    else if (jsoneq(file_content, &g[k], DST_PORT_KEY) == 0)
                    {
                        /* We may use strndup() to fetch string value */
                        printf("- %s: %.*s\n", DST_PORT_KEY, g[k + 1].end - g[k + 1].start,
                               file_content + g[k + 1].start);

                        char port[10];
                        strncpy(port, file_content + g[k + 1].start, g[k + 1].end - g[k + 1].start);
                        port[g[k + 1].end - g[k + 1].start] = 0;
                        dst_port = atoi(port);

                        k++;
                    }
                    else
                    {
                        printf("Unexpected key: %.*s\n", g[k].end - g[k].start,
                               file_content + g[k].start);
                    }
                }
                i += k - 1;

                struct packet_config config;
                memset(&config, 0, sizeof(struct packet_config));

                strcpy(config.src_ip, src_ip);
                strcpy(config.dst_ip, dst_ip);
                strcpy(config.dst_mac, dst_mac);
                config.dst_port = dst_port;

                resolve_packet_configurations(&config, &((*configs)[j]));
                config_count++;
            }

            i += t[i + 1].size + 1;
        }
    }

    free(file_content);
    return config_count;
}
