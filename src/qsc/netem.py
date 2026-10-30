"""Minimal user-space link emulator (TCP relay) for Platform D.

    client --TCP--> [ relay: one-way delay d, bandwidth R per direction, FIFO ] --TCP--> server

Each chunk read from one side is scheduled on a FIFO link:
    tx_start  = max(arrival, link_free)
    link_free = tx_start + 8 * len / R           (serialization delay)
    deliver   = link_free + d                    (propagation delay, RTT = 2d)
and written to the other side at `deliver`. Pure Python, no root, works on Windows/macOS/Linux.

Not modelled (stated in platform_D.md): packet loss / retransmission, TCP congestion window
dynamics on the emulated hop, jitter, MTU/packetisation (TCP/IP header bytes).
"""
from __future__ import annotations

import queue
import socket
import threading
import time


def _pump(src, dst, one_way_s, bps):
    q: queue.Queue = queue.Queue()
    state = {"free": 0.0}

    def reader():
        try:
            while True:
                data = src.recv(65536)
                now = time.perf_counter()
                if not data:
                    q.put((now + one_way_s, None))
                    return
                start = max(now, state["free"])
                state["free"] = start + (8 * len(data) / bps if bps else 0.0)
                q.put((state["free"] + one_way_s, data))
        except OSError:
            q.put((0.0, None))

    def writer():
        while True:
            at, data = q.get()
            delay = at - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            if data is None:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            try:
                dst.sendall(data)
            except OSError:
                return

    threads = [threading.Thread(target=reader, daemon=True), threading.Thread(target=writer, daemon=True)]
    for t in threads:
        t.start()
    return threads


def _handle(client_sock, target, one_way_s, bps):
    try:
        server_sock = socket.create_connection(target)
    except OSError:
        client_sock.close()
        return
    for s in (client_sock, server_sock):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ts = _pump(client_sock, server_sock, one_way_s, bps) + _pump(server_sock, client_sock, one_way_s, bps)
    for t in ts:
        t.join()
    client_sock.close()
    server_sock.close()


def relay_main(target_port, rtt_ms, mbps, ready, host="127.0.0.1"):
    """Process entry point: listen on an ephemeral port, relay to target_port through the emulated link."""
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind((host, 0))
    lst.listen(64)
    ready.put(lst.getsockname()[1])
    one_way = rtt_ms / 2000.0
    bps = mbps * 1e6
    while True:
        c, _ = lst.accept()
        threading.Thread(target=_handle, args=(c, (host, target_port), one_way, bps), daemon=True).start()
