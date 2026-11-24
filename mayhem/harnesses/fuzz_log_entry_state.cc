// Fuzz the persisted-state formats: log_entry::deserialize (log store / wire
// log entries) and srv_state::deserialize (v0 and v1+ server-state records).
// The first byte selects the format; the rest is the record.
#include "libnuraft/nuraft.hxx"
#include <cstring>
#include <stdexcept>

using namespace nuraft;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    uint8_t sel = data[0];
    data++; size--;
    ptr<buffer> buf = buffer::alloc(size);
    memcpy(buf->data_begin(), data, size);
    buf->pos(0);
    try {
        if (sel & 1) {
            ptr<srv_state> s = srv_state::deserialize(*buf);
            if (s) {
                ptr<buffer> out = s->serialize();
                out->pos(0);
                srv_state::deserialize(*out);
            }
        } else {
            ptr<log_entry> e = log_entry::deserialize(*buf);
            if (e) {
                ptr<buffer> out = e->serialize();
                out->pos(0);
                log_entry::deserialize(*out);
            }
        }
    } catch (std::exception&) {
    }
    return 0;
}
