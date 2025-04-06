from .alarm_ccexport cimport AlarmConnection as AlarmConnectionCC

def _to_bytes(v):
    if not isinstance(v, (str, bytes)):
        v = str(v)
    if isinstance(v, str):
        return v.encode('utf-8')
    return v

cdef class AlarmConnection:
    cdef AlarmConnectionCC cc_obj

    def __cinit__(self, ip=None, port=None):
        if ip is not None and port is not None:
            self.cc_obj = AlarmConnectionCC(_to_bytes(ip), port)
        else:
            self.cc_obj = AlarmConnectionCC()

    def connect(self, ip, port):
        self.cc_obj.connect(ip, port)

    def disconnect(self):
        self.cc_obj.disconnect()

    def receive_data(self):
        return [
            m.decode('utf-8') for m in self.cc_obj.receive_data()
        ]

    def query_alarm(self):
        self.cc_obj.query_alarm()
