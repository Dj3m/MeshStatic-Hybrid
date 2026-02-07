#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include "../../common/mesh_protocol.h"

// Конфигурация
#define MESH_CHANNEL 1
#define SEND_INTERVAL 60000  // 1 минута
#define SIMULATED_TEMP 25.0f

uint8_t self_mac[6];
uint32_t last_send = 0;

// Отправка данных с датчика
void send_sensor_data() {
    MeshPacketHeader packet;
    
    packet.network_id = MESH_NETWORK_ID;
    packet.version = PROTOCOL_VERSION;
    packet.ttl = DEFAULT_TTL;
    packet.packet_id = millis();
    memcpy(packet.src_mac, self_mac, 6);
    memcpy(packet.dst_mac, BROADCAST_MAC, 6);
    memcpy(packet.last_hop_mac, self_mac, 6);
    packet.msg_type = MSG_DATA_SENSOR;
    packet.flags = FLAG_REQUIRE_ACK;
    packet.group_id = 0x0001;  // Группа температурных датчиков
    
    // Данные датчика
    SensorData sensor_data;
    sensor_data.device_type = 0x01;  // Температурный датчик
    sensor_data.timestamp = millis() / 1000;
    
    #ifdef USE_SIMULATED_SENSOR
        sensor_data.temperature = SIMULATED_TEMP + (random(-50, 50) / 10.0);
        sensor_data.humidity = 50.0f + (random(-200, 200) / 10.0);
    #else
        // Здесь будет код для реального датчика DHT22/BME280
        sensor_data.temperature = 25.0f;
        sensor_data.humidity = 50.0f;
    #endif
    
    sensor_data.battery_mv = 3300;  // 3.3V
    sensor_data.rssi = -60;
    sensor_data.accuracy = 95;
    
    memcpy(packet.payload, &sensor_data, sizeof(sensor_data));
    
    // Отправка
    esp_err_t result = esp_now_send(BROADCAST_MAC, (uint8_t*)&packet, sizeof(packet));
    
    if (result == ESP_OK) {
        Serial.printf("Sent: %.1f°C, %.1f%%\n", 
                     sensor_data.temperature, sensor_data.humidity);
    } else {
        Serial.printf("Send error: %d\n", result);
    }
}

// Callback при отправке
void on_espnow_send(const uint8_t* mac, esp_now_send_status_t status) {
    if (status == ESP_NOW_SEND_SUCCESS) {
        Serial.println("Delivery success");
    } else {
        Serial.println("Delivery failed");
    }
}

void setup() {
    Serial.begin(115200);
    delay(2000);  // Даем время для подключения к Serial
    
    Serial.println("\n=== MeshStatic Temperature Sensor ===");
    
    WiFi.macAddress(self_mac);
    Serial.print("MAC: ");
    
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             self_mac[0], self_mac[1], self_mac[2],
             self_mac[3], self_mac[4], self_mac[5]);
    Serial.println(mac_str);
    
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    // Инициализация ESP-NOW
    WiFi.channel(MESH_CHANNEL);
    
    if (esp_now_init() != ESP_OK) {
        Serial.println("ESP-NOW init failed");
        ESP.restart();
    }
    
    esp_now_register_send_cb(on_espnow_send);
    
    // Добавляем широковещательный peer
    esp_now_peer_info_t peer_info = {};
    memcpy(peer_info.peer_addr, BROADCAST_MAC, 6);
    peer_info.channel = MESH_CHANNEL;
    peer_info.encrypt = false;
    esp_now_add_peer(&peer_info);
    
    Serial.println("Sensor ready. Starting transmissions...");
    last_send = millis();
}

void loop() {
    if (millis() - last_send > SEND_INTERVAL) {
        send_sensor_data();
        last_send = millis();
    }
    
    // Слушаем команды по Serial
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        
        if (cmd == "send") {
            send_sensor_data();
        } else if (cmd == "status") {
            Serial.printf("Uptime: %lu sec\n", millis() / 1000);
            Serial.printf("Free heap: %lu bytes\n", ESP.getFreeHeap());
        } else if (cmd == "help") {
            Serial.println("Commands: send, status, help");
        }
    }
    
    delay(100);
}
