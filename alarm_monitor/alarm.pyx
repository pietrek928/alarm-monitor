from .alarm_ccexport cimport (
    AlarmConnection as AlarmConnectionCC,
    numbers_to_mask as numbers_to_mask_cc
)

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

    def send_arm(self, code, partitions):
        self.cc_obj.send_arm(int(code, 16), numbers_to_mask_cc(partitions))

    def send_disarm(self, code, partitions):
        self.cc_obj.send_disarm(int(code, 16), numbers_to_mask_cc(partitions))

    def describe_move(self):
        return self.cc_obj.describe_move().decode('utf-8')

    def query_alarm(self):
        self.cc_obj.query_alarm()

    def query_move(self):
        self.cc_obj.query_move()
