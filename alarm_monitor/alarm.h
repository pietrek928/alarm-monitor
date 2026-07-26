#pragma once

#include <cstdint>
#include <string>
#include <vector>

constexpr int MAX_PACKET = 64;

uint32_t numbers_to_mask(const std::vector<int> &partitions);

class AlarmConnection {
    int sock = -1;
    uint32_t alarm_state = 0, move_state = 0;
    uint8_t packet_buf[MAX_PACKET];
    int packet_state = 0;
    uint8_t packet_last_byte = 0;

    void process_packet(const uint8_t *buf, int size,
                        std::vector<std::string> &messages_out);
    void send_arm_cmd(uint8_t cmd, uint16_t code, uint32_t partitions);

  public:
    AlarmConnection();
    AlarmConnection(const std::string &ip, uint16_t port);

    AlarmConnection(const AlarmConnection &) = delete;
    AlarmConnection &operator=(const AlarmConnection &) = delete;

    AlarmConnection(AlarmConnection &&other) noexcept;
    AlarmConnection &operator=(AlarmConnection &&other) noexcept;

    ~AlarmConnection();

    void connect(const std::string &ip, uint16_t port);
    void disconnect() noexcept;
    std::vector<std::string> receive_data();
    std::string describe_move();
    void query_alarm();
    void query_move();
    void query_armed_partitions();
    void send_arm(uint16_t code, uint32_t partitions);
    void send_disarm(uint16_t code, uint32_t partitions);
};
