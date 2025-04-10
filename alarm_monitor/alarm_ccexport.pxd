from libcpp.vector cimport vector
from libcpp.string cimport string
from libc.stdint cimport uint16_t, uint32_t


cdef extern from "alarm.cc":
    uint32_t numbers_to_mask(vector[int] &partitions)

    cdef cppclass AlarmConnection:
        AlarmConnection()
        AlarmConnection(const string& ip, uint16_t port)
        void connect(const string& ip, uint16_t port)
        void disconnect()
        vector[string] receive_data()
        void send_arm(uint16_t code, uint32_t partitions)
        void send_disarm(uint16_t code, uint32_t partitions)
        string describe_move()
        void query_alarm()
        void query_move()
