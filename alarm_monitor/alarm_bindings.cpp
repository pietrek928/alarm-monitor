#include <cstdint>
#include <string>
#include <vector>

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include "alarm.hpp"

namespace nb = nanobind;

NB_MODULE(alarm, m) {
  nb::class_<AlarmConnection>(m, "AlarmConnection")
      .def(nb::init<>())
      .def(nb::init<const std::string &, uint16_t>())
      .def("connect", &AlarmConnection::connect)
      .def("disconnect", &AlarmConnection::disconnect)
      .def("receive_data", &AlarmConnection::receive_data)
      .def("describe_move", &AlarmConnection::describe_move)
      .def("query_alarm", &AlarmConnection::query_alarm)
      .def("query_move", &AlarmConnection::query_move)
      .def("query_armed_partitions", &AlarmConnection::query_armed_partitions)
      .def("send_arm",
           [](AlarmConnection &self, const std::string &code,
              const std::vector<int> &partitions) {
             self.send_arm(static_cast<uint16_t>(std::stoul(code, nullptr, 16)),
                           numbers_to_mask(partitions));
           })
      .def("send_disarm",
           [](AlarmConnection &self, const std::string &code,
              const std::vector<int> &partitions) {
             self.send_disarm(
                 static_cast<uint16_t>(std::stoul(code, nullptr, 16)),
                 numbers_to_mask(partitions));
           });
}
