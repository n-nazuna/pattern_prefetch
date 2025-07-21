from bcc import BPF
import ctypes
from time import sleep

bpf_source = """
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 dev_low;
    u32 dev_high;
    u64 sector;
    u32 size;
    u32 rwbs;
    bool is_request;
};

BPF_PERF_OUTPUT(events);

int trace_submit_bio(struct pt_regs *ctx, struct bio *bio) {
    struct data_t data = {};
    data.dev_low = bio->bi_bdev->bd_dev & 0xFFFFF;
    data.dev_high = bio->bi_bdev->bd_dev >> 20;
    data.sector = bio->bi_iter.bi_sector;
    data.size = bio->bi_iter.bi_size;
    data.rwbs = bio->bi_opf;
    data.is_request = true;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_bio_endio(struct pt_regs *ctx, struct bio *bio) {
    struct data_t data = {};
    data.dev_low = bio->bi_bdev->bd_dev & 0xFFFFF;
    data.dev_high = bio->bi_bdev->bd_dev >> 20;
    data.sector = bio->bi_iter.bi_sector;
    data.size = bio->bi_iter.bi_size;
    data.rwbs = bio->bi_opf;
    data.is_request = false;
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_source)

class Data(ctypes.Structure):
    _fields_ = [
        ("dev_low", ctypes.c_uint),
        ("dev_high", ctypes.c_uint),
        ("sector", ctypes.c_ulonglong),
        ("size", ctypes.c_uint),
        ("rwbs", ctypes.c_uint),
        ("is_request", ctypes.c_bool),
    ]

b.attach_kprobe(event="submit_bio", fn_name="trace_submit_bio")
b.attach_kprobe(event="bio_endio", fn_name="trace_bio_endio")

# イベントを受信する関数
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print(f"dev: [{event.dev_high:<3}:{event.dev_low:<3}], ops: {event.rwbs:<32b}, lba: {event.sector:<16X}, blk: {event.size:<8}, rq: {event.is_request and 'RQ' or 'CQ'}")

# perf bufferの設定と開始
b["events"].open_perf_buffer(print_event)

print("Tracing block I/O... Hit Ctrl-C to stop.")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Done.")
