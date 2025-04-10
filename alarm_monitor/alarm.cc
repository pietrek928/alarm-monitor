#include <cstring>
#include <stdexcept>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <sys/types.h>
#include <vector>
#include <iostream>

#include <arpa/inet.h> //inet_addr
#include <fcntl.h>     // for open
#include <string>
#include <sys/socket.h> //socket
#include <unistd.h>

#define PACKED __attribute__((packed))


constexpr static uint8_t STOP_BYTE = 0xFE;
constexpr static uint8_t STOP_BYTE_ENCODE = 0xF0;
constexpr static uint8_t PACKET_END_BYTE = 0x0D;

typedef enum {
    MOVE = 0x00,
    ALTAMP = 0x01,
    AL = 0x02,
    ARMED_PARTITIONS_SUPPRESSED = 0x09,
    ARMED_PARTITIONS_REALLY = 0x0A,
    ARMED_PARTITIONS_MODE_2 = 0x0B,
    ARMED_PARTITIONS_MODE_3 = 0x0C,
    RETURN_CODE = 0xEF,
} ALARM_QUERY;
typedef enum {
  ARM_MODE_0 = 0x80,
  ARM_MODE_1 = 0x81,
  ARM_MODE_2 = 0x82,
  ARM_MODE_3 = 0x83,
  DISARM = 0x84,
  CLEAR_ALARM = 0x85,
  ZONES_BYPASS = 0x86,
  ZONES_UNBYPASS = 0x87,
  OUTPUTS_ON = 0x88,
  OUTPUTS_OFF = 0x89,
  OPEN_DOOR = 0x8A,
  CLEAR_TROUBLE = 0x8B,
  READ_EVENT = 0x8C,
  GET_TEXT_EVENT = 0x8F,
} ALARM_CMD;

std::string return_code_to_string_en(uint8_t code) {
  switch (code) {
    case 0x00: return "ok";
    case 0x01: return "requesting user code not found";
    case 0x02: return "no access";
    case 0x03: return "selected user does not exist";
    case 0x04: return "selected user already exists";
    case 0x05: return "wrong code or code already exists";
    case 0x06: return "telephone code already exists";
    case 0x07: return "changed code is the same";
    case 0x08: return "other error";
    case 0x11: return "can not arm, but can use force arm";
    case 0x12: return "can not arm";
    case 0xFF: return "command accepted";
    default: return "unknown return code " + std::to_string(code);
  }
}

std::string return_code_to_string_pl(uint8_t code) {
  switch (code) {
    case 0x00: return "ok";
    case 0x01: return "nie znaleziono kodu użytkownika";
    case 0x02: return "brak dostępu";
    case 0x03: return "nie istnieje wybrany użytkownik";
    case 0x04: return "wybrany użytkownik już istnieje";
    case 0x05: return "zły kod lub kod już istnieje";
    case 0x06: return "kod telefonu już istnieje";
    case 0x07: return "nowy kod jest taki sam jak stary";
    case 0x08: return "inny błąd";
    case 0x11: return "zazbrojenie niemożliwe, ale można wymusić";
    case 0x12: return "zazbrojenie niemożliwe";
    case 0xFF: return "komenda zaakceptowana";
    default: return "nieznany kod odpowiedzi " + std::to_string(code);
  }
}


typedef struct arm_packet_t {
  uint8_t cmd = 0;
  union {
    uint8_t b[8];
    u_int64_t w = -1;
  } pass;
  uint32_t partitions = 0;
} PACKED arm_packet_t;

constexpr static int MAX_PACKET = 64;

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
  tv.tv_usec = 0;          // Not init'ing this can cause strange errors
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
        messages_out.push_back("Alarm w strefie " + std::to_string(it));
      } else {
        messages_out.push_back("Koniec alarmu w strefie " + std::to_string(it));
      }
    }

    old_zones >>= 1;
    new_zones >>= 1;
  }
}

std::string describe_move_state(uint32_t move_state) {
  if (!move_state) return "Brak ruchu";

  std::string descr = "Wykryto ruch w strefach:";
  int it = 1;
  while (move_state != 0) {
    if (move_state & 1) {
      descr += " " + std::to_string(it);
    }
    move_state >>= 1;
    it++;
  }
  return descr;
}

uint32_t numbers_to_mask(
  const std::vector<int> &partitions
) {
  uint32_t r = 0;
  for (int p : partitions) {
    r |= 1 << (p - 1);
  }
  return r;
}

class AlarmConnection {
    int sock = -1;
    uint32_t alarm_state = 0, move_state = 0;
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
      ALARM_QUERY code = (ALARM_QUERY)buf[0];
      buf++;
      size--;

      switch (code) {
        case AL: {
          uint32_t new_alarm_state = get_num(buf, size);
          compare_alarm_state(alarm_state, new_alarm_state, messages_out);
          alarm_state = new_alarm_state;
        } break;
        case MOVE:
          move_state = get_num(buf, size);
          break;
        case RETURN_CODE:
          messages_out.push_back(return_code_to_string_pl(buf[0]));
          break;
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

    std::string describe_move() {
      return describe_move_state(move_state);
    }

    void query_alarm() {
      uint8_t q = ALARM_QUERY::AL;
      uint8_t send_buf[MAX_PACKET];
      int send_len = prepare_alarm_packet(send_buf, &q, 1);
      send_data(sock, send_buf, send_len);
    }

    void query_move() {
      uint8_t q = ALARM_QUERY::MOVE;
      uint8_t send_buf[MAX_PACKET];
      int send_len = prepare_alarm_packet(send_buf, &q, 1);
      send_data(sock, send_buf, send_len);
    }

    void send_arm_cmd(
      uint8_t cmd, uint16_t code, uint32_t partitions
    ) {
      arm_packet_t p;
      p.cmd = cmd;
      p.pass.b[0] = code >> 8;
      p.pass.b[1] = code;
      p.partitions = partitions;
      uint8_t send_buf[MAX_PACKET];
      int send_len = prepare_alarm_packet(send_buf, (uint8_t *)&p, sizeof(p));
      send_data(sock, send_buf, send_len);
    }

    void send_arm(
      uint16_t code, uint32_t partitions
    ) {
      send_arm_cmd(ALARM_CMD::ARM_MODE_0, code, partitions);
    }

    void send_disarm(
      uint16_t code, uint32_t partitions
    ) {
      send_arm_cmd(ALARM_CMD::DISARM, code, partitions);
    }
};
