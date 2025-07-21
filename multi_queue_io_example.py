import os
import threading

SECTOR_SIZE = 512
BLOCK_SIZE = 4096

def pread_task(fd, offset):
    try:
        data = os.pread(fd, BLOCK_SIZE, offset)
        print(f"Read {len(data)} bytes at offset {offset}")
    except OSError as e:
        print(f"Failed offset:{offset}, fd:{fd}, error:{e}")

def warmup_parallel(path, lba_list):
    fd = os.open(path, os.O_RDWR)
    threads = []

    for lba in lba_list:
        offset = lba * SECTOR_SIZE
        t = threading.Thread(target=pread_task, args=(fd, offset))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    os.close(fd)

if __name__ == "__main__":
    path = "/dev/sdc"  # Replace with your actual device path
    import random
    n = 128
    lba_list = [random.randint(0, 0x100000) for _ in range(n)]
    alighned_list = [x * 4096 for x in lba_list]


    warmup_parallel(path, alighned_list)
    print("Warmup completed.")