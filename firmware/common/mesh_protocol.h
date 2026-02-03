// mesh_protocol.h - Ядро протокола MeshStatic
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define MESH_NETWORK_ID         0xFA23
#define PROTOCOL_VERSION        0x01
#define MAX_PACKET_SIZE         250
#define DEFAULT_TTL             7
static const uint8_t BROADCAST_MAC[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

typedef enum {
    MSG_DATA_SENSOR        = 0x01,
    MSG_DATA_ACTUATOR      = 0x02,
    MSG_CMD_SET            = 0x03,
    MSG_CMD_GET            = 0x04,
    MSG_ROUTING_UPDATE     = 0x05,
    MSG_HEARTBEAT          = 0x06,
    MSG_DISCOVERY          = 0x07,
    MSG_CMD_GROUP          = 0x08,
    MSG_EVENT_BROADCAST    = 0x09,
    MSG_DEVICE_STATE_UPDATE= 0x0A,
    MSG_ACK                = 0x0E,
    MSG_NACK               = 0x0F
} MessageType;

typedef enum {
    FLAG_REQUIRE_ACK     = (1 << 0),
    FLAG_LOCAL_PROCESS   = (1 << 1),
    FLAG_EMERGENCY       = (1 << 2),
    FLAG_ENCRYPTED       = (1 << 3),
    FLAG_BROADCAST       = (1 << 6)
} PacketFlags;

#pragma pack(push, 1)
typedef struct {
    uint16_t network_id;
    uint8_t  version;
    uint8_t  ttl;
    uint32_t packet_id;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  last_hop_mac[6];
    uint8_t  msg_type;
    uint8_t  flags;
    uint16_t group_id;
    uint8_t  payload[180];
} MeshPacketHeader;

typedef struct {
    uint16_t device_type;
    uint32_t timestamp;
    float    temperature;
    float    humidity;
    uint16_t battery_mv;
    int8_t   rssi;
    uint8_t  accuracy;
} SensorData;

typedef struct {
    uint16_t group_id;
    uint8_t  command_code;
    uint8_t  parameter_len;
    uint8_t  parameters[16];
} GroupCommand;
#pragma pack(pop)

static inline bool validate_packet(const MeshPacketHeader* pkt, size_t len) {
    return (len >= sizeof(MeshPacketHeader)) &&
           (pkt->network_id == MESH_NETWORK_ID) &&
           (pkt->version == PROTOCOL_VERSION) &&
           (pkt->ttl > 0);
}

static inline void decrement_ttl(MeshPacketHeader* pkt) {
    if (pkt->ttl > 0) pkt->ttl--;
}

static inline bool is_broadcast_packet(const MeshPacketHeader* pkt) {
    return memcmp(pkt->dst_mac, BROADCAST_MAC, 6) == 0;
}

static inline bool is_for_me(const MeshPacketHeader* pkt, const uint8_t* my_mac) {
    return memcmp(pkt->dst_mac, my_mac, 6) == 0;
}

static inline bool requires_local_processing(const MeshPacketHeader* pkt) {
    return (pkt->flags & FLAG_LOCAL_PROCESS) != 0;
}

static inline bool requires_ack(const MeshPacketHeader* pkt) {
    return (pkt->flags & FLAG_REQUIRE_ACK) != 0;
}

static inline bool is_emergency(const MeshPacketHeader* pkt) {
    return (pkt->flags & FLAG_EMERGENCY) != 0;
}