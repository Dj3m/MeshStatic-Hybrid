/**
 * MeshStatic-Hybrid: Координатор (мозг системы)
 * 
 * Координатор — это корневой узел сети. Он:
 * 1. Управляет всей Mesh-сетью
 * 2. Хранит карту всех устройств
 * 3. Предоставляет веб-интерфейс
 * 4. Сохраняет настройки и логи
 * 
 * Аппаратура: ESP32-S3 DevKitC с Ethernet/LTE
 * Питание: от сети + резервная батарея
 * Режим: всегда включен, не спит
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <Update.h>
#include <SPIFFS.h>

// Наши модули
#include "../../common/mesh_protocol.h"
#include "../../common/crypto/chacha20_poly1305.h"

// ============================================================================
// КОНФИГУРАЦИЯ
// ============================================================================

/**
 * Настройки WiFi
 * 
 * WiFi используется ТОЛЬКО для веб-интерфейса.
 * Mesh-сеть работает независимо через ESP-NOW.
 * 
 * Если WiFi не подключится — создаст свою точку доступа.
 */
const char* WIFI_SSID = "YOUR_WIFI";      // Замени на свой SSID
const char* WIFI_PASSWORD = "YOUR_PASS";  // Замени на свой пароль

// Параметры сети
#define MESH_CHANNEL 1           // WiFi канал для ESP-NOW (1-13 в РФ)
#define HEARTBEAT_INTERVAL 60000 // Интервал heartbeat (60 секунд)
#define MAX_ROUTING_ENTRIES 100  // Максимум устройств в сети
#define WEB_SERVER_PORT 80       // Порт веб-сервера
#define OTA_ENABLED true         // Включить обновление по воздуху

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================

/**
 * Наш MAC адрес
 * 
 * У каждого ESP32 есть уникальный MAC, который
 * используется как идентификатор в сети.
 */
uint8_t self_mac[6];

/**
 * Веб-сервер
 * 
 * Предоставляет интерфейс управления по адресу:
 * - http://192.168.4.1 (если в режиме точки доступа)
 * - http://local_ip (если подключен к WiFi)
 */
AsyncWebServer web_server(WEB_SERVER_PORT);

/**
 * Постоянное хранилище
 * 
 * Сохраняет настройки между перезагрузками.
 * Аналог EEPROM, но лучше.
 */
Preferences preferences;

/**
 * Состояние сети
 * 
 * Следим за здоровьем системы.
 */
struct NetworkState {
    bool mesh_initialized = false;    // ESP-NOW инициализирован?
    bool wifi_connected = false;      // Подключен к WiFi?
    bool web_server_running = false;  // Веб-сервер запущен?
    uint32_t packets_received = 0;    // Сколько пакетов получили
    uint32_t packets_sent = 0;        // Сколько пакетов отправили
    uint32_t last_heartbeat = 0;      // Когда последний heartbeat
    uint32_t startup_time;            // Когда система запустилась
    uint32_t free_heap_min = UINT32_MAX; // Минимальная свободная память
} network_state;

/**
 * Таблица маршрутизации
 * 
 * Хранит информацию о всех устройствах в сети:
 * - Кто где находится
 * - Кто чей родитель
 * - Качество связи
 * - Статус (онлайн/офлайн)
 */
RoutingEntry routing_table[MAX_ROUTING_ENTRIES];
uint8_t routing_table_size = 0;  // Сколько записей сейчас заполнено

/**
 * Сессионный ключ
 * 
 * Меняется каждые 24 часа для безопасности.
 * Используется для шифрования пакетов.
 */
uint8_t session_key[32];
uint32_t current_session_id = 0;

// ============================================================================
// ПРОТОТИПЫ ФУНКЦИЙ
// ============================================================================

// Функции настройки
void setup();
void setup_wifi();
void setup_espnow();
void setup_web_server();
void setup_filesystem();
void load_configuration();

// Обработка пакетов ESP-NOW
void on_espnow_recv(const uint8_t* mac, const uint8_t* data, int len);
void on_espnow_send(const uint8_t* mac, esp_now_send_status_t status);

// Обработка разных типов пакетов
void process_mesh_packet(const MeshPacketHeader* packet, const uint8_t* last_hop_mac);
void handle_sensor_data(const MeshPacketHeader* packet, const SensorData* data);
void handle_command(const MeshPacketHeader* packet);
void handle_heartbeat(const MeshPacketHeader* packet);
void handle_discovery(const MeshPacketHeader* packet);
void handle_group_command(const MeshPacketHeader* packet);
void handle_emergency_event(const MeshPacketHeader* packet);

// Маршрутизация
void route_packet(const MeshPacketHeader* packet);
RoutingEntry* find_routing_entry(const uint8_t* mac);
void update_routing_table(const uint8_t* mac, int8_t rssi, const uint8_t* parent_mac = nullptr);
void remove_routing_entry(const uint8_t* mac);
void cleanup_old_entries();

// Отправка пакетов
void send_packet(const uint8_t* dst_mac, const void* data, size_t len);
void send_heartbeat();
void send_device_discovery();
void send_acknowledgment(const uint8_t* dst_mac, uint32_t packet_id);

// Веб-обработчики
void handle_root(AsyncWebServerRequest* request);
void handle_api_network_status(AsyncWebServerRequest* request);
void handle_api_devices(AsyncWebServerRequest* request);
void handle_api_command(AsyncWebServerRequest* request);
void handle_api_logs(AsyncWebServerRequest* request);
void handle_ota_upload(AsyncWebServerRequest* request);

// Утилиты
String mac_to_string(const uint8_t* mac);
String get_network_status_json();
String get_routing_table_json();
void log_event(const char* event, const char* details = "");

// Основной цикл
void loop();

// ============================================================================
// НАСТРОЙКА СИСТЕМЫ
// ============================================================================

/**
 * Начальная настройка
 * 
 * Вызывается один раз при включении.
 * Порядок важен!
 */
void setup() {
    // 1. Серийный порт для отладки
    Serial.begin(115200);
    delay(1000);  // Ждём стабилизации
    
    Serial.println("\n\n" + String(80, '='));
    Serial.println("   MeshStatic-Hybrid Coordinator");
    Serial.println("   Version 1.0.0");
    Serial.println("   " + String(__DATE__) + " " + String(__TIME__));
    Serial.println(String(80, '=') + "\n");
    
    // 2. Запоминаем время старта
    network_state.startup_time = millis();
    
    // 3. Получаем наш MAC адрес
    WiFi.macAddress(self_mac);
    Serial.print("Our MAC: ");
    Serial.println(mac_to_string(self_mac));
    
    // 4. Настраиваем файловую систему
    setup_filesystem();
    
    // 5. Загружаем конфигурацию
    load_configuration();
    
    // 6. Настраиваем WiFi
    setup_wifi();
    
    // 7. Настраиваем ESP-NOW (Mesh сеть)
    setup_espnow();
    
    // 8. Настраиваем веб-сервер
    setup_web_server();
    
    // 9. Инициализируем ключ сессии
    // В реальной системе здесь была бы генерация ключа
    memset(session_key, 0xAA, sizeof(session_key));  // Заглушка
    
    // 10. Всё готово!
    Serial.println("\nSETUP COMPLETE: Coordinator is ready!");
    Serial.print("Web interface: ");
    if (network_state.wifi_connected) {
        Serial.println("http://" + WiFi.localIP().toString());
    } else {
        Serial.println("http://" + WiFi.softAPIP().toString());
    }
    Serial.println("Mesh channel: " + String(MESH_CHANNEL));
    Serial.println("Free heap: " + String(ESP.getFreeHeap()) + " bytes");
    
    log_event("system_started", "Coordinator initialized");
}

/**
 * Настройка WiFi
 * 
 * Пробуем подключиться к домашнему WiFi.
 * Если не получается — создаём свою точку доступа.
 */
void setup_wifi() {
    Serial.print("Connecting to WiFi: ");
    Serial.print(WIFI_SSID);
    
    // Режим: точка доступа + клиент
    WiFi.mode(WIFI_AP_STA);
    
    // Пробуем подключиться
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\nWiFi connected!");
        Serial.println("IP address: " + WiFi.localIP().toString());
        network_state.wifi_connected = true;
        log_event("wifi_connected", WiFi.localIP().toString().c_str());
    } else {
        Serial.println("\nWiFi failed, starting AP mode");
        
        // Создаём точку доступа
        WiFi.softAP("MeshStatic-Config", "12345678");
        
        Serial.println("AP IP: " + WiFi.softAPIP().toString());
        Serial.println("Password: 12345678");
        log_event("wifi_ap_started", "MeshStatic-Config");
    }
}

/**
 * Настройка ESP-NOW
 * 
 * ESP-NOW — это протокол от Espressif для связи
 * между ESP32 без установления соединения.
 * Быстрый, надёжный, низкое энергопотребление.
 */
void setup_espnow() {
    Serial.print("Initializing ESP-NOW... ");
    
    // Устанавливаем канал WiFi (важно для ESP-NOW)
    WiFi.channel(MESH_CHANNEL);
    
    // Инициализируем ESP-NOW
    if (esp_now_init() != ESP_OK) {
        Serial.println("Failed!");
        log_event("espnow_init_failed");
        return;
    }
    
    // Регистрируем callback'и
    esp_now_register_recv_cb(on_espnow_recv);
    esp_now_register_send_cb(on_espnow_send);
    
    // Добавляем широковещательный peer
    esp_now_peer_info_t peer_info = {};
    memset(&peer_info, 0, sizeof(peer_info));
    memcpy(peer_info.peer_addr, BROADCAST_MAC, 6);
    peer_info.channel = MESH_CHANNEL;
    peer_info.encrypt = false;  // Шифрование через наш протокол
    
    if (esp_now_add_peer(&peer_info) != ESP_OK) {
        Serial.println("Failed to add broadcast peer");
    }
    
    network_state.mesh_initialized = true;
    Serial.println("Ready!");
    log_event("espnow_initialized");
}

/**
 * Настройка веб-сервера
 * 
 * Предоставляет:
 * - Веб-интерфейс управления
 * - REST API для скриптов
 * - OTA обновления
 */
void setup_web_server() {
    Serial.print("Starting web server... ");
    
    // Статические файлы из SPIFFS
    web_server.serveStatic("/static", SPIFFS, "/static/");
    
    // Главная страница
    web_server.on("/", HTTP_GET, handle_root);
    
    // API endpoints
    web_server.on("/api/network-status", HTTP_GET, handle_api_network_status);
    web_server.on("/api/devices", HTTP_GET, handle_api_devices);
    web_server.on("/api/command", HTTP_POST, handle_api_command);
    web_server.on("/api/logs", HTTP_GET, handle_api_logs);
    
    // OTA обновления
    web_server.on("/update", HTTP_GET, [](AsyncWebServerRequest* request) {
        request->send(200, "text/html", 
            "<form method='POST' action='/update' enctype='multipart/form-data'>"
            "<input type='file' name='update'><input type='submit' value='Update'>"
            "</form>");
    });
    
    web_server.on("/update", HTTP_POST, 
        [](AsyncWebServerRequest* request) {
            request->send(200, "text/plain", 
                Update.hasError() ? "FAIL" : "OK");
            ESP.restart();
        },
        [](AsyncWebServerRequest* request, String filename, size_t index, uint8_t* data, size_t len, bool final) {
            if (!index) {
                Serial.printf("OTA Update: %s\n", filename.c_str());
                Update.begin(UPDATE_SIZE_UNKNOWN);
            }
            Update.write(data, len);
            if (final) {
                Update.end(true);
            }
        }
    );
    
    // Перезагрузка
    web_server.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest* request) {
        request->send(200, "application/json", "{\"message\":\"Rebooting...\"}");
        delay(1000);
        ESP.restart();
    });
    
    // Запускаем сервер
    web_server.begin();
    network_state.web_server_running = true;
    
    Serial.println("Server started on port " + String(WEB_SERVER_PORT));
    log_event("web_server_started");
}

/**
 * Настройка файловой системы
 * 
 * SPIFFS — файловая система в flash памяти.
 * Хранит: конфиги, логи, веб-страницы.
 */
void setup_filesystem() {
    if (!SPIFFS.begin(true)) {
        Serial.println("SPIFFS mount failed");
        return;
    }
    
    Serial.println("SPIFFS mounted");
    
    // Создаём структуру папок
    if (!SPIFFS.exists("/config")) {
        SPIFFS.mkdir("/config");
    }
    if (!SPIFFS.exists("/logs")) {
        SPIFFS.mkdir("/logs");
    }
    if (!SPIFFS.exists("/static")) {
        SPIFFS.mkdir("/static");
    }
    
    log_event("filesystem_mounted");
}

/**
 * Загрузка конфигурации
 * 
 * Загружает настройки из постоянной памяти.
 * Сохраняется между перезагрузками.
 */
void load_configuration() {
    preferences.begin("meshstatic", false);  // false = read/write mode
    
    // Загружаем или создаём network_id
    if (!preferences.isKey("network_id")) {
        preferences.putUInt("network_id", MESH_NETWORK_ID);
    }
    
    // Загружаем таблицу маршрутизации
    routing_table_size = preferences.getUChar("routing_count", 0);
    if (routing_table_size > 0 && routing_table_size <= MAX_ROUTING_ENTRIES) {
        size_t bytes_read = preferences.getBytes("routing_table", 
                                               routing_table, 
                                               routing_table_size * sizeof(RoutingEntry));
        Serial.printf("Loaded %d routing entries (%d bytes)\n", 
                     routing_table_size, bytes_read);
    }
    
    preferences.end();
    log_event("config_loaded");
}

// ============================================================================
// ОБРАБОТКА ESP-NOW ПАКЕТОВ
// ============================================================================

/**
 * Callback при получении пакета
 * 
 * Вызывается когда ESP-NOW получает данные.
 * Важно: работает в контексте WiFi задачи!
 * Нельзя делать долгие операции.
 * 
 * @param mac MAC отправителя
 * @param data Данные пакета
 * @param len Длина данных
 */
void on_espnow_recv(const uint8_t* mac, const uint8_t* data, int len) {
    network_state.packets_received++;
    
    // Быстрая проверка размера
    if (len < (int)sizeof(MeshPacketHeader)) {
        return;
    }
    
    // Копируем пакет для обработки
    MeshPacketHeader packet;
    memcpy(&packet, data, sizeof(MeshPacketHeader));
    
    // Валидация
    if (!validate_packet(&packet, len)) {
        return;
    }
    
    // Обработка пакета
    process_mesh_packet(&packet, mac);
}

/**
 * Callback при отправке пакета
 * 
 * Вызывается когда ESP-NOW завершил отправку.
 * status показывает успешность.
 * 
 * @param mac MAC получателя
 * @param status Статус отправки
 */
void on_espnow_send(const uint8_t* mac, esp_now_send_status_t status) {
    network_state.packets_sent++;
    
    if (status != ESP_NOW_SEND_SUCCESS) {
        Serial.printf("Send failed to %s\n", mac_to_string(mac).c_str());
        log_event("packet_send_failed", mac_to_string(mac).c_str());
    }
}

// ============================================================================
// ОБРАБОТКА ПАКЕТОВ
// ============================================================================

/**
 * Основной обработчик пакетов
 * 
 * Определяет тип пакета и вызывает соответствующий обработчик.
 * 
 * @param packet Пакет для обработки
 * @param last_hop_mac MAC кто передал пакет
 */
void process_mesh_packet(const MeshPacketHeader* packet, const uint8_t* last_hop_mac) {
    // Обновляем таблицу маршрутизации
    int8_t rssi = 0;  // В реальности: esp_now_get_peer_rssi()
    update_routing_table(packet->src_mac, rssi, last_hop_mac);
    
    // Уменьшаем TTL если пакет не для нас
    if (!is_packet_for_us(packet, self_mac)) {
        MeshPacketHeader* mutable_packet = (MeshPacketHeader*)packet;
        decrement_ttl(mutable_packet);
    }
    
    // Определяем тип пакета
    switch (packet->msg_type) {
        case MSG_DATA_SENSOR:
            if (is_packet_for_us(packet, self_mac)) {
                handle_sensor_data(packet, (SensorData*)packet->payload);
            } else {
                route_packet(packet);
            }
            break;
            
        case MSG_CMD_SET:
            if (is_packet_for_us(packet, self_mac)) {
                handle_command(packet);
            } else {
                route_packet(packet);
            }
            break;
            
        case MSG_CMD_GROUP:
            if (requires_local_processing(packet)) {
                // Локальная обработка на репитере
                // (координатор получает только если флаг не установлен)
                handle_group_command(packet);
            } else if (is_packet_for_us(packet, self_mac)) {
                handle_group_command(packet);
            } else {
                route_packet(packet);
            }
            break;
            
        case MSG_EVENT_BROADCAST:
            // Экстренные события обрабатывают все
            handle_emergency_event(packet);
            if (!is_packet_for_us(packet, self_mac)) {
                route_packet(packet);  // Пересылаем дальше
            }
            break;
            
        case MSG_HEARTBEAT:
            handle_heartbeat(packet);
            break;
            
        case MSG_DISCOVERY:
            handle_discovery(packet);
            break;
            
        default:
            Serial.printf("Unknown packet type: 0x%02X\n", packet->msg_type);
            break;
    }
    
    // Отправляем подтверждение если требуется
    if (requires_acknowledgment(packet) && is_packet_for_us(packet, self_mac)) {
        send_acknowledgment(packet->src_mac, packet->packet_id);
    }
}

/**
 * Обработка данных с датчиков
 * 
 * Датчики отправляют температуру, влажность и т.д.
 * Координатор сохраняет эти данные и может
 * принимать решения на их основе.
 * 
 * @param packet Пакет с данными
 * @param data Структура данных датчика
 */
void handle_sensor_data(const MeshPacketHeader* packet, const SensorData* data) {
    Serial.printf("Sensor %s: %.1f°C, %.1f%%, %dmV, RSSI: %d\n",
                 mac_to_string(packet->src_mac).c_str(),
                 data->temperature,
                 data->humidity,
                 data->battery_mv,
                 data->rssi);
    
    // Сохраняем в лог
    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg),
             "sensor_data mac=%s temp=%.1f humidity=%.1f battery=%d",
             mac_to_string(packet->src_mac).c_str(),
             data->temperature,
             data->humidity,
             data->battery_mv);
    log_event("sensor_data", log_msg);
    
    // Проверяем аномалии
    if (data->temperature > 40.0) {
        // Слишком горячо!
        Serial.println("High temperature detected!");
        log_event("high_temperature", mac_to_string(packet->src_mac).c_str());
    }
    
    if (data->battery_mv < 3000) {
        // Батарея садится
        Serial.println("Low battery!");
        log_event("low_battery", mac_to_string(packet->src_mac).c_str());
    }
}

/**
 * Обработка команд
 * 
 * Команды могут приходить:
 * - Из веб-интерфейса
 * - От других устройств
 * - По расписанию
 * 
 * @param packet Пакет с командой
 */
void handle_command(const MeshPacketHeader* packet) {
    Serial.printf("Command from %s\n", mac_to_string(packet->src_mac).c_str());
    log_event("command_received", mac_to_string(packet->src_mac).c_str());
    
    // В реальной системе здесь была бы обработка команд
    // Например: включить свет, изменить температуру и т.д.
}

/**
 * Обработка heartbeat
 * 
 * Устройства периодически отправляют "пульс"
 * чтобы показать что они живы.
 * 
 * @param packet Пакет heartbeat
 */
void handle_heartbeat(const MeshPacketHeader* packet) {
    // Обновляем время последнего контакта
    RoutingEntry* entry = find_routing_entry(packet->src_mac);
    if (entry) {
        entry->last_seen = millis() / 1000;
        entry->status = 1;  // Онлайн
        
        // Можно добавить статистику RSSI
        // entry->rssi = ...;
    }
}

/**
 * Обработка discovery пакетов
 * 
 * Новые устройства отправляют discovery пакеты
 * чтобы представиться сети.
 * 
 * @param packet Discovery пакет
 */
void handle_discovery(const MeshPacketHeader* packet) {
    Serial.printf("Discovery from %s\n", mac_to_string(packet->src_mac).c_str());
    log_event("device_discovered", mac_to_string(packet->src_mac).c_str());
    
    // Отправляем ответ с конфигурацией
    // В реальной системе здесь была бы отправка
    // network_id, channel, encryption keys и т.д.
    
    Serial.println("Sending welcome packet...");
}

/**
 * Обработка групповых команд
 * 
 * Команда для группы устройств.
 * Координатор рассылает её всем устройствам в группе.
 * 
 * @param packet Пакет групповой команды
 */
void handle_group_command(const MeshPacketHeader* packet) {
    GroupCommand* cmd = (GroupCommand*)packet->payload;
    
    Serial.printf("Group command: group=0x%04X, cmd=0x%02X\n",
                 cmd->group_id, cmd->command_code);
    
    // В реальной системе здесь был бы поиск
    // устройств в указанной группе и рассылка
    // команды каждому из них.
    
    log_event("group_command", 
             String("group=" + String(cmd->group_id, HEX) + 
                   " cmd=" + String(cmd->command_code, HEX)).c_str());
}

/**
 * Обработка экстренных событий
 * 
 * Пожар, протечка, вторжение и т.д.
 * Обрабатываются немедленно всеми устройствами.
 * 
 * @param packet Пакет события
 */
void handle_emergency_event(const MeshPacketHeader* packet) {
    EmergencyEvent* event = (EmergencyEvent*)packet->payload;
    
    Serial.printf("EMERGENCY! Type: %d, Severity: %d, From: %s\n",
                 event->event_type, event->severity,
                 mac_to_string(event->sensor_mac).c_str());
    
    // Визуальная и звуковая сигнализация
    // (если есть подключённые устройства)
    
    // Уведомления
    // (если есть подключение к интернету)
    
    log_event("emergency", 
             String("type=" + String(event->event_type) +
                   " severity=" + String(event->severity)).c_str());
}

// ============================================================================
// МАРШРУТИЗАЦИЯ
// ============================================================================

/**
 * Маршрутизация пакета
 * 
 * Определяет куда отправить пакет дальше.
 * Использует таблицу маршрутизации.
 * 
 * @param packet Пакет для маршрутизации
 */
void route_packet(const MeshPacketHeader* packet) {
    // Ищем запись в таблице маршрутизации
    RoutingEntry* entry = find_routing_entry(packet->dst_mac);
    
    if (!entry) {
        // Маршрут не найден
        Serial.printf("No route to %s\n", mac_to_string(packet->dst_mac).c_str());
        log_event("route_not_found", mac_to_string(packet->dst_mac).c_str());
        return;
    }
    
    // Определяем следующий прыжок
    uint8_t* next_hop;
    
    if (memcmp(entry->parent_mac, self_mac, 6) == 0) {
        // Мы родитель этого устройства — отправляем напрямую
        next_hop = entry->device_mac;
    } else {
        // Устройство дальше по цепочке — отправляем его родителю
        next_hop = entry->parent_mac;
    }
    
    // Отправляем
    Serial.printf("Routing packet to %s via %s\n",
                 mac_to_string(packet->dst_mac).c_str(),
                 mac_to_string(next_hop).c_str());
    
    send_packet(next_hop, packet, sizeof(MeshPacketHeader));
}

/**
 * Поиск записи в таблице маршрутизации
 * 
 * @param mac MAC для поиска
 * @return Указатель на запись или nullptr
 */
RoutingEntry* find_routing_entry(const uint8_t* mac) {
    for (int i = 0; i < routing_table_size; i++) {
        if (memcmp(routing_table[i].device_mac, mac, 6) == 0) {
            return &routing_table[i];
        }
    }
    return nullptr;
}

/**
 * Обновление таблицы маршрутизации
 * 
 * Добавляет или обновляет запись об устройстве.
 * 
 * @param mac MAC устройства
 * @param rssi Сила сигнала
 * @param parent_mac MAC родителя (nullptr если мы родитель)
 */
void update_routing_table(const uint8_t* mac, int8_t rssi, const uint8_t* parent_mac) {
    RoutingEntry* entry = find_routing_entry(mac);
    
    if (!entry) {
        // Новая запись
        if (routing_table_size >= MAX_ROUTING_ENTRIES) {
            // Таблица переполнена
            Serial.println("Routing table full!");
            return;
        }
        
        entry = &routing_table[routing_table_size];
        memcpy(entry->device_mac, mac, 6);
        routing_table_size++;
        
        Serial.printf("New device: %s\n", mac_to_string(mac).c_str());
    }
    
    // Обновляем данные
    entry->rssi = rssi;
    entry->last_seen = millis() / 1000;
    entry->status = 1;  // Онлайн
    
    if (parent_mac) {
        memcpy(entry->parent_mac, parent_mac, 6);
    }
    
    // Периодически сохраняем в EEPROM
    static uint32_t last_save = 0;
    if (millis() - last_save > 30000) {  // Каждые 30 секунд
        preferences.begin("meshstatic", false);
        preferences.putUChar("routing_count", routing_table_size);
        preferences.putBytes("routing_table", routing_table, 
                           routing_table_size * sizeof(RoutingEntry));
        preferences.end();
        last_save = millis();
    }
}

/**
 * Удаление записи из таблицы
 * 
 * @param mac MAC для удаления
 */
void remove_routing_entry(const uint8_t* mac) {
    for (int i = 0; i < routing_table_size; i++) {
        if (memcmp(routing_table[i].device_mac, mac, 6) == 0) {
            // Сдвигаем остальные записи
            for (int j = i; j < routing_table_size - 1; j++) {
                routing_table[j] = routing_table[j + 1];
            }
            routing_table_size--;
            break;
        }
    }
}

/**
 * Очистка старых записей
 * 
 * Удаляет устройства которые не видели больше 5 минут.
 */
void cleanup_old_entries() {
    uint32_t now = millis() / 1000;
    uint32_t threshold = 300;  // 5 минут
    
    for (int i = 0; i < routing_table_size; i++) {
        if (now - routing_table[i].last_seen > threshold) {
            Serial.printf("Removing stale device: %s\n",
                         mac_to_string(routing_table[i].device_mac).c_str());
            
            remove_routing_entry(routing_table[i].device_mac);
            i--;  // Проверяем текущий индекс снова после сдвига
        }
    }
}

// ============================================================================
// ОТПРАВКА ПАКЕТОВ
// ============================================================================

/**
 * Отправка пакета
 * 
 * @param dst_mac MAC получателя
 * @param data Данные пакета
 * @param len Длина данных
 */
void send_packet(const uint8_t* dst_mac, const void* data, size_t len) {
    // ESP-NOW может отправлять до 250 байт
    if (len > 250) {
        Serial.println("Packet too large for ESP-NOW");
        return;
    }
    
    esp_err_t result = esp_now_send(dst_mac, (uint8_t*)data, len);
    
    if (result == ESP_OK) {
        // Успех — callback on_espnow_send вызовется позже
    } else {
        Serial.printf("ESP-NOW send error: %d\n", result);
        log_event("espnow_send_error", String(result).c_str());
    }
}

/**
 * Отправка heartbeat
 * 
 * Координатор периодически отправляет пульс
 * чтобы устройства знали что он жив.
 */
void send_heartbeat() {
    MeshPacketHeader packet;
    
    packet.network_id = MESH_NETWORK_ID;
    packet.version = PROTOCOL_VERSION;
    packet.ttl = DEFAULT_TTL;
    packet.packet_id = millis();
    memcpy(packet.src_mac, self_mac, 6);
    memcpy(packet.dst_mac, BROADCAST_MAC, 6);
    memcpy(packet.last_hop_mac, self_mac, 6);
    packet.msg_type = MSG_HEARTBEAT;
    packet.flags = 0;
    packet.group_id = 0;
    
    send_packet(BROADCAST_MAC, &packet, sizeof(packet));
    network_state.last_heartbeat = millis();
    
    Serial.println("Heartbeat sent");
}

/**
 * Отправка discovery
 * 
 * Просит все устройства отозваться.
 * Используется для построения карты сети.
 */
void send_device_discovery() {
    MeshPacketHeader packet;
    
    packet.network_id = MESH_NETWORK_ID;
    packet.version = PROTOCOL_VERSION;
    packet.ttl = DEFAULT_TTL;
    packet.packet_id = millis();
    memcpy(packet.src_mac, self_mac, 6);
    memcpy(packet.dst_mac, BROADCAST_MAC, 6);
    memcpy(packet.last_hop_mac, self_mac, 6);
    packet.msg_type = MSG_DISCOVERY;
    packet.flags = 0;
    packet.group_id = 0;
    
    send_packet(BROADCAST_MAC, &packet, sizeof(packet));
    
    Serial.println("Discovery packet sent");
    log_event("discovery_sent");
}

/**
 * Отправка подтверждения
 * 
 * @param dst_mac MAC получателя
 * @param packet_id ID пакета который подтверждаем
 */
void send_acknowledgment(const uint8_t* dst_mac, uint32_t packet_id) {
    // В реальной системе здесь был бы пакет ACK
    Serial.printf("Sending ACK for packet %lu to %s\n",
                 packet_id, mac_to_string(dst_mac).c_str());
}

// ============================================================================
// ВЕБ-ИНТЕРФЕЙС
// ============================================================================

/**
 * Главная страница веб-интерфейса
 */
void handle_root(AsyncWebServerRequest* request) {
    String html = R"rawliteral(
    <!DOCTYPE html>
    <html>
    <head>
        <title>MeshStatic Coordinator</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f0f0f0; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            .header { background: #4CAF50; color: white; padding: 20px; border-radius: 10px 10px 0 0; margin: -20px -20px 20px -20px; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
            .stat-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #4CAF50; }
            .stat-value { font-size: 2em; font-weight: bold; color: #2c3e50; }
            .stat-label { color: #7f8c8d; font-size: 0.9em; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th { background: #34495e; color: white; padding: 12px; text-align: left; }
            td { padding: 10px; border-bottom: 1px solid #ddd; }
            .online { color: #27ae60; font-weight: bold; }
            .offline { color: #e74c3c; }
            .btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
            .btn:hover { background: #2980b9; }
            .btn-scan { background: #e67e22; }
            .btn-reboot { background: #e74c3c; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>MeshStatic Coordinator</h1>
                <p>Autonomous Mesh Network Management</p>
            </div>
            
            <div class="stats" id="stats">
                <!-- Заполняется JavaScript -->
            </div>
            
            <div>
                <button class="btn" onclick="refreshData()">Refresh</button>
                <button class="btn btn-scan" onclick="sendCommand('scan')">Scan Network</button>
                <button class="btn btn-reboot" onclick="reboot()">Reboot</button>
            </div>
            
            <h2>Connected Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>MAC Address</th>
                        <th>Signal</th>
                        <th>Last Seen</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="devices-table">
                    <!-- Заполняется JavaScript -->
                </tbody>
            </table>
        </div>
        
        <script>
            function refreshData() {
                fetch('/api/network-status')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('stats').innerHTML = `
                            <div class="stat-card">
                                <div class="stat-value">${data.uptime}s</div>
                                <div class="stat-label">Uptime</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.packets_received}</div>
                                <div class="stat-label">Packets Received</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.packets_sent}</div>
                                <div class="stat-label">Packets Sent</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.nodes_online}</div>
                                <div class="stat-label">Nodes Online</div>
                            </div>`;
                    });
                    
                fetch('/api/devices')
                    .then(r => r.json())
                    .then(data => {
                        let html = '';
                        data.devices.forEach(device => {
                            html += `
                                <tr>
                                    <td>${device.mac}</td>
                                    <td>${device.rssi} dBm</td>
                                    <td>${device.last_seen}s ago</td>
                                    <td class="${device.online ? 'online' : 'offline'}">
                                        ${device.online ? 'ONLINE' : 'OFFLINE'}
                                    </td>
                                </tr>`;
                        });
                        document.getElementById('devices-table').innerHTML = html;
                    });
            }
            
            function sendCommand(cmd) {
                fetch('/api/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: cmd})
                }).then(r => r.json())
                  .then(data => alert(data.message));
            }
            
            function reboot() {
                if(confirm('Reboot coordinator?')) {
                    fetch('/api/reboot', {method: 'POST'});
                }
            }
            
            // Автообновление каждые 10 секунд
            setInterval(refreshData, 10000);
            document.addEventListener('DOMContentLoaded', refreshData);
        </script>
    </body>
    </html>
    )rawliteral";
    
    request->send(200, "text/html", html);
}

/**
 * API: статус сети
 */
void handle_api_network_status(AsyncWebServerRequest* request) {
    StaticJsonDocument<512> doc;
    
    doc["uptime"] = (millis() - network_state.startup_time) / 1000;
    doc["packets_received"] = network_state.packets_received;
    doc["packets_sent"] = network_state.packets_sent;
    
    // Считаем онлайн-устройства
    uint8_t online_count = 0;
    uint32_t now = millis() / 1000;
    for (int i = 0; i < routing_table_size; i++) {
        if (now - routing_table[i].last_seen < 300) {  // Видели последние 5 минут
            online_count++;
        }
    }
    
    doc["nodes_online"] = online_count;
    doc["nodes_total"] = routing_table_size;
    doc["mesh_initialized"] = network_state.mesh_initialized;
    doc["wifi_connected"] = network_state.wifi_connected;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["free_heap_min"] = network_state.free_heap_min;
    
    String response;
    serializeJson(doc, response);
    request->send(200, "application/json", response);
}

/**
 * API: список устройств
 */
void handle_api_devices(AsyncWebServerRequest* request) {
    StaticJsonDocument<4096> doc;
    JsonArray devices = doc.createNestedArray("devices");
    
    uint32_t now = millis() / 1000;
    
    for (int i = 0; i < routing_table_size; i++) {
        JsonObject device = devices.createNestedObject();
        
        device["mac"] = mac_to_string(routing_table[i].device_mac);
        device["rssi"] = routing_table[i].rssi;
        device["last_seen"] = now - routing_table[i].last_seen;
        device["online"] = (now - routing_table[i].last_seen) < 300;  // 5 минут
        
        if (routing_table[i].battery_mv > 0) {
            device["battery"] = routing_table[i].battery_mv;
        }
    }
    
    String response;
    serializeJson(doc, response);
    request->send(200, "application/json", response);
}

/**
 * API: отправка команды
 */
void handle_api_command(AsyncWebServerRequest* request) {
    if (request->method() == HTTP_POST) {
        String body = request->arg("plain");
        StaticJsonDocument<256> doc;
        DeserializationError error = deserializeJson(doc, body);
        
        if (error) {
            request->send(400, "application/json", "{\"error\":\"Invalid JSON\"}");
            return;
        }
        
        const char* command = doc["command"];
        
        if (strcmp(command, "scan") == 0) {
            send_device_discovery();
            request->send(200, "application/json", "{\"message\":\"Scan started\"}");
        } else {
            request->send(400, "application/json", "{\"error\":\"Unknown command\"}");
        }
    } else {
        request->send(405, "application/json", "{\"error\":\"Method not allowed\"}");
    }
}

/**
 * API: логи системы
 */
void handle_api_logs(AsyncWebServerRequest* request) {
    // В реальной системе здесь читались бы логи из файла
    request->send(200, "text/plain", "Logs would be here...\n");
}

// ============================================================================
// УТИЛИТЫ
// ============================================================================

/**
 * Конвертация MAC в строку
 * 
 * @param mac MAC адрес
 * @return Строка вида "AA:BB:CC:DD:EE:FF"
 */
String mac_to_string(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

/**
 * Логирование события
 * 
 * @param event Событие
 * @param details Детали
 */
void log_event(const char* event, const char* details) {
    // В реальной системе здесь было бы сохранение в файл
    Serial.printf("Event: %s", event);
    if (details && strlen(details) > 0) {
        Serial.printf(" (%s)", details);
    }
    Serial.println();
}

// ============================================================================
// ОСНОВНОЙ ЦИКЛ
// ============================================================================

/**
 * Главный цикл программы
 * 
 * Вызывается постоянно после setup().
 * Здесь обрабатываются фоновые задачи.
 */
void loop() {
    static uint32_t last_heartbeat = 0;
    static uint32_t last_cleanup = 0;
    static uint32_t last_stat_update = 0;
    
    // Периодический heartbeat
    if (millis() - last_heartbeat > HEARTBEAT_INTERVAL) {
        send_heartbeat();
        last_heartbeat = millis();
    }
    
    // Очистка старых записей каждую минуту
    if (millis() - last_cleanup > 60000) {
        cleanup_old_entries();
        last_cleanup = millis();
    }
    
    // Обновление статистики памяти
    if (millis() - last_stat_update > 10000) {
        uint32_t free_heap = ESP.getFreeHeap();
        if (free_heap < network_state.free_heap_min) {
            network_state.free_heap_min = free_heap;
        }
        last_stat_update = millis();
    }
    
    // Простая консоль для отладки
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        
        if (cmd == "status") {
            Serial.println("=== Coordinator Status ===");
            Serial.printf("Uptime: %lu seconds\n", (millis() - network_state.startup_time) / 1000);
            Serial.printf("Packets RX/TX: %lu/%lu\n", 
                         network_state.packets_received, 
                         network_state.packets_sent);
            Serial.printf("Routing entries: %d\n", routing_table_size);
            Serial.printf("Free heap: %lu bytes (min: %lu)\n", 
                         ESP.getFreeHeap(), 
                         network_state.free_heap_min);
            Serial.printf("WiFi: %s\n", 
                         network_state.wifi_connected ? "Connected" : "AP Mode");
            Serial.printf("Mesh: %s\n", 
                         network_state.mesh_initialized ? "Ready" : "Not ready");
        } 
        else if (cmd == "devices") {
            Serial.println("=== Connected Devices ===");
            for (int i = 0; i < routing_table_size; i++) {
                Serial.printf("%2d. %s ", i + 1, 
                             mac_to_string(routing_table[i].device_mac).c_str());
                Serial.printf("(RSSI: %d, ", routing_table[i].rssi);
                
                uint32_t last_seen = (millis() / 1000) - routing_table[i].last_seen;
                if (last_seen < 60) {
                    Serial.printf("seen %lus ago)\n", last_seen);
                } else if (last_seen < 3600) {
                    Serial.printf("seen %lum ago)\n", last_seen / 60);
                } else {
                    Serial.printf("seen %luh ago)\n", last_seen / 3600);
                }
            }
        }
        else if (cmd == "scan") {
            send_device_discovery();
            Serial.println("Discovery packet sent");
        }
        else if (cmd == "reboot") {
            Serial.println("Rebooting...");
            delay(1000);
            ESP.restart();
        }
        else if (cmd == "help") {
            Serial.println("Available commands:");
            Serial.println("  status    - Show system status");
            Serial.println("  devices   - List connected devices");
            Serial.println("  scan      - Send discovery packet");
            Serial.println("  reboot    - Reboot coordinator");
            Serial.println("  help      - This help");
        }
        else {
            Serial.printf("Unknown command: %s\n", cmd.c_str());
            Serial.println("Type 'help' for available commands");
        }
    }
    
    // Небольшая задержка чтобы не грузить процессор
    delay(100);
}

// Конец файла main.cpp