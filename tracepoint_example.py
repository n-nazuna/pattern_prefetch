from bcc import BPF
from bcc.utils import printb
import ctypes
from collections import defaultdict

# eBPFプログラム
bpf_text = """
struct data_t {
    u32 dev_low;
    u32 dev_high;
    u64 sector;
    u32 size;
    char rwbs[8];
    bool is_request;
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(block, block_bio_queue) {
    struct data_t data = {};
    data.dev_high = args->dev >> 20;
    data.dev_low = args->dev & 0xFFFFF;
    data.sector = args->sector;
    data.size = args->nr_sector;
    __builtin_memcpy(&data.rwbs, args->rwbs, sizeof(data.rwbs));
    data.is_request = true;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
TRACEPOINT_PROBE(block, block_bio_complete) {
    struct data_t data = {};
    data.dev_high = args->dev >> 20;
    data.dev_low = args->dev & 0xFFFFF;
    data.sector = args->sector;
    data.size = args->nr_sector;
    __builtin_memcpy(&data.rwbs, args->rwbs, sizeof(data.rwbs));
    data.is_request = false;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# BPFプログラムのロード
b = BPF(text=bpf_text)

# ユーザー空間用データ構造体定義（Python側）
class Data(ctypes.Structure):
    _fields_ = [
        ("dev_low", ctypes.c_uint),
        ("dev_high", ctypes.c_uint),
        ("sector", ctypes.c_ulonglong),
        ("size", ctypes.c_uint),
        ("rwbs", ctypes.c_char * 8),
        ("is_request", ctypes.c_bool),
    ]

# イベントを受信する関数
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print(f"dev: [{event.dev_high:<3}:{event.dev_low:<3}], ops: {event.rwbs.decode('ascii'):<8}, lba: {event.sector:<16X}, blk: {event.size:<8}, rq: {event.is_request and 'RQ' or 'CQ'}")

# perf bufferの設定と開始
b["events"].open_perf_buffer(print_event)

print("Tracing block I/O... Hit Ctrl-C to stop.")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Done.")
