// Fuzz snapshot_sync_req::deserialize (which parses a snapshot and its nested
// cluster_config): the payload of an install_snapshot request from the leader.
#include "libnuraft/nuraft.hxx"
#include <cstring>
#include <stdexcept>

using namespace nuraft;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    ptr<buffer> buf = buffer::alloc(size);
    memcpy(buf->data_begin(), data, size);
    buf->pos(0);
    try {
        ptr<snapshot_sync_req> r = snapshot_sync_req::deserialize(*buf);
        if (r) {
            ptr<buffer> out = r->serialize();
            out->pos(0);
            snapshot_sync_req::deserialize(*out);
        }
    } catch (std::exception&) {
    }
    return 0;
}
