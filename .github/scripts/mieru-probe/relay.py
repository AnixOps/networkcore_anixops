#!/usr/bin/env python3
"""Loopback TCP relay that records both directions as JSON lines.

Black-box wire probe for the clean-room Mieru outbound: it sits between the
official mieru client and the official mita server, both running in CI.
Usage: relay.py LISTEN_PORT TARGET_PORT LOG_FILE
"""
import asyncio
import json
import sys
import time

listen_port, target_port, log_path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
counter = 0
log = open(log_path, "a", buffering=1)


async def pump(conn, direction, reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            log.write(json.dumps({"conn": conn, "dir": direction, "t": time.time(), "hex": data.hex()}) + "\n")
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        log.write(json.dumps({"conn": conn, "dir": direction, "t": time.time(), "eof": True}) + "\n")
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            writer.close()


async def handle(client_reader, client_writer):
    global counter
    counter += 1
    conn = counter
    server_reader, server_writer = await asyncio.open_connection("127.0.0.1", target_port)
    await asyncio.gather(
        pump(conn, "c2s", client_reader, server_writer),
        pump(conn, "s2c", server_reader, client_writer),
    )
    client_writer.close()
    server_writer.close()


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", listen_port)
    async with server:
        await server.serve_forever()


asyncio.run(main())
