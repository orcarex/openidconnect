import os
import threading
import asyncio
import multiprocessing
import psutil
from random import randint
from time import sleep

# 一個簡單的計算函數，模擬一些 CPU 工作
def compute():
    sleep(randint(1,5)) # 模擬一些計算延遲
    return sum(i * i for i in range(10**2))

# 測量記憶體使用
def print_memory_usage(label):
    process = psutil.Process(os.getpid())
    print(f"{label} memory usage: {process.memory_info().rss / 1024 ** 2:.2f} MB")

# 多進程
def multiprocessing_example():
    processes = []
    for _ in range(9999):
        p = multiprocessing.Process(target=compute)
        processes.append(p)
        p.start()
    for p in processes:
        p.join()

# 多線程
def threading_example():
    threads = []
    for _ in range(9999):
        t = threading.Thread(target=compute)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# 協程
async def coroutine_example():
    async def async_compute():
        return compute()

    tasks = [async_compute() for _ in range(199)]
    await asyncio.gather(*tasks)

if __name__ == '__main__':
    print_memory_usage("Initial")
    
    # 測試多進程
    multiprocessing_example()
    print_memory_usage("After multiprocessing")

    # 測試多線程
    # threading_example()
    # print_memory_usage("After threading")

    # 測試協程
    # asyncio.run(coroutine_example())
    # print_memory_usage("After coroutines")
