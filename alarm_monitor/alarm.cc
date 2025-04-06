#include <cstring>
#include <stdexcept>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include <arpa/inet.h> //inet_addr
#include <fcntl.h>     // for open
#include <string>
#include <sys/socket.h> //socket
#include <unistd.h>


constexpr static uint8_t STOP_BYTE = 0xFE;
constexpr static uint8_t STOP_BYTE_ENCODE = 0xF0;
constexpr static uint8_t PACKET_END_BYTE = 0x0D;

typedef enum {
    MOVE = 0x00,
    ALTAMP = 0x01,
    AL = 0x02,
} ALARM_CMD;
// #define Q_AL_MEM
// #define Q_ALTAMP_MEM

constexpr static int MAX_PACKET = 64;
constexpr static int ZONES_MAX_SIZE = 32;

void network_error(const char *msg) {
  throw std::runtime_error((std::string)msg + ": " + strerror(errno));
}

int alarm_connect(const char *ip, const uint16_t port, int timeout_sec = 30) {
  struct sockaddr_in server;
  int sock;

  // Create socket
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    network_error("creating socket failed");

  struct timeval tv;
  tv.tv_sec = timeout_sec; /* 30 Secs Timeout */
  tv.tv_usec = 0; // Not init'ing this can cause strange errors
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
                 sizeof(struct timeval)))
    network_error("setsockopt failed");

  server.sin_addr.s_addr = inet_addr(ip);
  server.sin_family = AF_INET;
  server.sin_port = htons(port);

  if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    network_error("connect error");

  return sock;
}

void alarm_disconnect(int sock) {
  if (close(sock) < 0)
    network_error("Could not close socket");
}

int recv_data(int sock, uint8_t *buf, int size) {
    int r = recv(sock, buf, size, 0);
    if (r < 0) network_error("Receiving data failed");
    return r;
}

void send_data(int sock, const uint8_t *buf, int size) {
    int sent = 0;
    while (sent < size) {
        int r = send(sock, buf + sent, size - sent, 0);
        if (r <= 0) network_error("Sending data failed");
        sent += r;
    }
}

uint32_t get_num(const uint8_t *buf, int l) {
    if (l >= 4) {
        return *(uint32_t *)buf;
    } else if (l >= 2) {
        return *(uint16_t *)buf;
    } else if (l >= 1) {
        return *(uint8_t *)buf;
    }
    return 0;
}

uint16_t compute_checksum(const uint8_t *data, int l) {
  int r = 0x147A;
  while (l--) {
    r = ((r << 1) | ((r >> 15) & 1));
    r = ~r;
    r += ((r >> 8) & 0xff) + *(data++);
  }
  return ((r & 0xff) << 8) | ((r >> 8) & 0xff);
}

int prepare_alarm_packet(uint8_t *out, const uint8_t *data, int size) {
  uint16_t checksum = compute_checksum(data, size);
  *(out++) = *(out++) = STOP_BYTE;
  int it = size;
  while (it--)
    *(out++) = *(data++);
  *((uint16_t *)out) = checksum;
  out += 2;
  *(out++) = STOP_BYTE;
  *(out++) = PACKET_END_BYTE;
  return size + 6;
}

int extract_alarm_packet(const uint8_t *data, int l, int &it,
                        uint8_t *packet_buf, int &packet_state, uint8_t &packet_last_byte) {
  while (packet_state < 0 && it < l)
    if (data[it++] == STOP_BYTE) {
      packet_state++;
      packet_last_byte = 0;
    } else
      packet_state = -2;

  while (it < l && packet_state < MAX_PACKET) {
    uint8_t current_byte = data[it++];
    if (packet_last_byte == STOP_BYTE) {

      switch (current_byte) {
      case PACKET_END_BYTE: {
        int packet_len = packet_state;
        packet_state = -2;
        packet_last_byte = 0;
        return packet_len;
      }
      case STOP_BYTE_ENCODE:
        packet_buf[packet_state++] = STOP_BYTE;
        break;
      case STOP_BYTE:
        packet_state = 0;
        packet_last_byte = 0;
        return 0;
      default:
        packet_state = -2;
        packet_last_byte = 0;
        return 0;
      }

    } else if (current_byte != STOP_BYTE)
      packet_buf[packet_state++] = current_byte;
    packet_last_byte = current_byte;
  }
  return 0;
}

void compare_alarm_state(uint32_t old_zones, uint32_t new_zones,
                         std::vector<std::string> &messages_out) {
  int it = 1;
  while (old_zones != new_zones) {
    bool old_val = old_zones & 1;
    bool new_val = new_zones & 1;
    if (old_val != new_val) {
      if (new_val) {
        messages_out.push_back("Alarm in zone " + std::to_string(it));
      } else {
        messages_out.push_back("Alarm out of zone " + std::to_string(it));
      }
    }

    old_zones >>= 1;
    new_zones >>= 1;
  }
}

class AlarmConnection {
    int sock = -1;
    uint32_t alarm_state = 0;
    uint8_t packet_buf[MAX_PACKET];
    int packet_state = 0;
    uint8_t packet_last_byte = 0;

    void process_packet(const uint8_t *buf, int size,
                        std::vector<std::string> &messages_out) {
      if (size < 3)
        return;
      uint16_t chk = compute_checksum(buf, size - 2);
      if (chk != *(uint16_t *)(buf + size - 2))
        return;
      size -= 2;
      /*int i;
      log( "packet length: %d", l );
      for ( i=0; i<l; i++ ) log( "char: %02X", buf[i]&0xff );//*/
      ALARM_CMD code = (ALARM_CMD)buf[0];
      buf++;
      size--;

      switch (code) {
      case AL: {
        uint32_t new_alarm_state = get_num(buf, size);
        compare_alarm_state(alarm_state, new_alarm_state, messages_out);
      } break;
      default:
        messages_out.push_back("Unknown packet type" + std::to_string(code));
      }
    }

  public:
    AlarmConnection() {}
    AlarmConnection(const std::string ip, const uint16_t port) {
        connect(ip, port);
    }

    // --- Delete Copy ---
    AlarmConnection(const AlarmConnection &) = delete;
    AlarmConnection &operator=(const AlarmConnection &) = delete;

    // --- Define Move ---
    AlarmConnection &operator=(AlarmConnection &&other) noexcept {
      if (this != &other) { // Prevent self-assignment
        disconnect();
        sock = other.sock;
        alarm_state = other.alarm_state;
        packet_state = other.packet_state;
        packet_last_byte = other.packet_last_byte;
        memcpy(packet_buf, other.packet_buf, MAX_PACKET);

        other.sock = -1;
        other.alarm_state = 0;
        other.packet_state = 0;
        other.packet_last_byte = 0;
      }
      return *this;
    }

    AlarmConnection(AlarmConnection &&other) noexcept {
      *this = std::move(other);
    }

    ~AlarmConnection() {
        disconnect();
    }

    void connect(const std::string ip, const uint16_t port) {
        sock = alarm_connect(ip.c_str(), port);
    }

    void disconnect() {
        if (sock != -1) {
            alarm_disconnect(sock);
            sock = -1;
        }
    }

    std::vector<std::string> receive_data() {
        std::vector<std::string> messages_out;
        int r = recv_data(sock, packet_buf, MAX_PACKET);

        int it = 0;
        while (it < r) {
            int packet_len = extract_alarm_packet(packet_buf, r, it, packet_buf, packet_state, packet_last_byte);
            if (packet_len > 0) {
                process_packet(packet_buf, packet_len, messages_out);
            }
        }
        return messages_out;
    }

    void query_alarm() {
      uint8_t q = ALARM_CMD::AL;
      uint8_t send_buf[MAX_PACKET];
      int send_len = prepare_alarm_packet(send_buf, &q, 1);
      send_data(sock, send_buf, send_len);
    }
};
