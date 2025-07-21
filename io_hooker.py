from bcc import BPF
import ctypes
import pandas as pd
from collections import deque

# 最大保持数
MAX_ENTRIES = 1000
data_deque = deque(maxlen=MAX_ENTRIES)  # ← ここがポイント！

# eBPFプログラム（略）
bpf_text = """
struct data_t {
    u32 dev_low;
    u32 dev_high;
    u64 sector_begin;
    u64 sector_end;
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(block, block_bio_queue) {
    struct data_t data = {};
    if (args->rwbs[0] == 'R' // ebpfではstring.hが使えないので力業でフィルタする
     || args->rwbs[1] == 'R'
     || args->rwbs[2] == 'R'
     || args->rwbs[3] == 'R'
     || args->rwbs[4] == 'R'
     || args->rwbs[5] == 'R'
     || args->rwbs[6] == 'R'
     || args->rwbs[7] == 'R') {
        data.dev_high = args->dev >> 20;
        data.dev_low = args->dev & 0xFFFFF;
        data.sector_begin = args->sector;
        data.sector_end = args->sector + args->nr_sector - 1; // sector_beginのlbaにもデータが書き込まれるので、block size(nr_sector)から1引く

        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""

# BPFロード
b = BPF(text=bpf_text)

# ユーザ空間データ構造体
class Data(ctypes.Structure):
    _fields_ = [
        ("dev_low", ctypes.c_uint),
        ("dev_high", ctypes.c_uint),
        ("sector_begin", ctypes.c_ulonglong),
        ("sector_end", ctypes.c_ulonglong),
    ]

# イベント受信処理
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    data_deque.append({
        "dev_high": event.dev_high,
        "dev_low": event.dev_low,
        "sector_begin": event.sector_begin,
        "sector_end": event.sector_end
    })

# perf buffer
b["events"].open_perf_buffer(print_event)

print("Tracing block I/O... Hit Ctrl-C to stop.")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Done.")

    # deque → DataFrame
    df = pd.DataFrame(data_deque)
    print(df)

    # CSV出力（オプション）
    df.to_csv("trace_latest1000.csv", index=False)
