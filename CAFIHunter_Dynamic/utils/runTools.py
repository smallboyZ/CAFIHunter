# -*- coding:utf-8 -*-
from multiprocessing import Process, Queue
from utils.adbTools import *
import traceback
import concurrent.futures
def _wrapper(q, func, args, kwargs):

    try:
        result = func(*args, **kwargs)
        q.put(("success", result))
    except Exception:
        q.put(("error", traceback.format_exc()))

def run_with_timeout(func, args=(), kwargs=None, timeout=5):

    if kwargs is None:
        kwargs = {}
    q = Queue()

    p = Process(target=_wrapper, args=(q, func, args, kwargs))
    p.start()
    p.join(timeout=timeout)

    if p.is_alive():
        p.terminate()
        p.join()
        return None

    if not q.empty():
        status, value = q.get()
        if status == "success":
            return value
        else:
            print("Function execution error: ")
            print(value)
            return None
    return None

def run_with_timeout_TP(func, *args, timeout=5, **kwargs):

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            log("Time Out!")
            return None
        except Exception as e:
            log("{e}")