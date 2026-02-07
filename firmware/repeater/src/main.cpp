#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>

#include "../../common/mesh_protocol.h"

// Конфигурация
#define MESH_CHANNEL 1
#define HEARTBEAT_INTERVAL 30000  // 30 сек для репитера

uint8_t self_mac[6];
bool mesh_initialized = false;

// Callback при получении пакета
void on_espnow_recv(const uint8_t* mac, const uint8_t* data, int len) {
    if (len < (int)sizeof(MeshPacketHeader)) return;
    
    MeshPacketHeader packet;
    memcpy(&packet, data, sizeof(MeshPacketHeader));
    
    if (!validate_packet(&packet, len)) return;
    
    // Если пакет не для нас и TTL > 0 - пересылаем
    if (!is_for_me(&packet, self_mac) && packet.ttl > 1) {
        // Уменьшаем TTL
        MeshPacketHeader* mutable_packet = (MeshPacketHeader*)data;
        decrement_ttl(mutable_packet);
        
        // Определяем куда пересылать
        // Пока просто широковещательно
        esp_now_send(BROADCAST_MAC, data, len);
        
        Serial.printf("Relayed packet from %s\n", 
                     mac_to_string(packet.src_mac).c_str());
    }
}

// Настройка ESP-NOW
void setup_espnow() {
    WiFi.channel(MESH_CHANNEL);
    
    if (esp_now_init() != ESP_OK) {
        Serial.println("ESP-NOW init failed");
        return;
    }
    
    esp_now_register_recv_cb(on_espnow_recv);
    
    // Добавляем широковещательный peer
    esp_now_peer_info_t peer_info = {};
    memcpy(peer_info.peer_addr, BROADCAST_MAC, 6);
    peer_info.channel = MESH_CHANNEL;
    peer_info.encrypt = false;
    esp_now_add_peer(&peer_info);
    
    mesh_initialized = true;
    Serial.println("Repeater: ESP-NOW ready");
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n=== MeshStatic Repeater Pro ===");
    
    WiFi.macAddress(self_mac);
    Serial.print("MAC: ");
    Serial.println(mac_to_string(self_mac).c_str());
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    setup_espnow();
    
    Serial.println("Repeater initialized. Waiting for packets...");
}

void loop() {
    // Простой loop - всё в callback'ах
    delay(100);
}

// Вспомогательная функция
String mac_to_string(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}
