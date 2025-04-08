from libcpp.vector cimport vector
from libcpp.string cimport string
from libc.stdint cimport uint16_t


cdef extern from "alarm.cc":
    cdef cppclass AlarmConnection:
        AlarmConnection()
        AlarmConnection(const string& ip, uint16_t port)
        void connect(const string& ip, uint16_t port)
        void disconnect()
        vector[string] receive_data()
        string describe_move()
        void query_alarm()
        void query_move()
