"""Bounded capture of subprocess output on Linux."""

from array import array
import fcntl
import os
import select
import termios


LINE_LIMIT = 4096
IDLE_POLL_MS = 20


def _discard_queued(source, sink):
    # Take a snapshot. Draining until the pipe is empty can starve capture
    # forever when the child is writing continuously.
    pending = array("i", [0])
    fcntl.ioctl(source, termios.FIONREAD, pending, True)
    remaining = pending[0]
    while remaining:
        try:
            count = os.splice(source, sink, min(remaining, LINE_LIMIT), flags=os.SPLICE_F_NONBLOCK)
        except BlockingIOError:
            break
        if not count:
            break
        remaining -= count
    return pending[0] != remaining


def capture_lines(pipe, enabled):
    """Yield bytes from a fresh pipe while a callable or Event permits capture.

    Long lines yield their first 4096 bytes. Paused output is discarded in the
    kernel. If any bytes were discarded while paused, skip through the next
    newline after resuming because the first resumed fragment may not be a
    complete line. An unterminated active line is yielded at EOF.
    """
    is_enabled = enabled if callable(enabled) else enabled.is_set
    fd = pipe.fileno()
    blocking = os.get_blocking(fd)
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    fragment = bytearray()
    capturing = is_enabled()
    discarded = False
    skip_fragment = False

    with open(os.devnull, "wb", buffering=0) as sink:
        os.set_blocking(fd, False)
        try:
            while True:
                if not is_enabled():
                    if capturing:
                        discarded = bool(fragment) or skip_fragment
                        fragment.clear()
                        capturing = False
                    try:
                        count = os.splice(fd, sink.fileno(), LINE_LIMIT, flags=os.SPLICE_F_NONBLOCK)
                    except BlockingIOError:
                        poller.poll(IDLE_POLL_MS)
                        continue
                    if not count:
                        return
                    discarded = True
                    continue

                if not capturing:
                    skip_fragment = _discard_queued(fd, sink.fileno()) or discarded
                    capturing = True
                    if not is_enabled():
                        continue

                try:
                    block = os.read(fd, LINE_LIMIT)
                except BlockingIOError:
                    poller.poll(IDLE_POLL_MS)
                    continue
                if not is_enabled():
                    discarded = bool(block) or bool(fragment) or skip_fragment
                    fragment.clear()
                    capturing = False
                    del block
                    continue
                if not block:
                    if fragment:
                        yield bytes(fragment)
                    return

                offset = 0
                while offset < len(block):
                    if not is_enabled():
                        fragment.clear()
                        discarded = True
                        capturing = False
                        break
                    newline = block.find(b"\n", offset)
                    end = len(block) if newline < 0 else newline + 1
                    if skip_fragment:
                        skip_fragment = newline < 0
                    else:
                        fragment.extend(block[offset:min(end, offset + LINE_LIMIT - len(fragment))])
                        if newline >= 0 or len(fragment) == LINE_LIMIT:
                            skip_fragment = newline < 0
                            result = bytes(fragment)
                            fragment.clear()
                            if is_enabled():
                                yield result
                            else:
                                discarded = True
                                capturing = False
                                break
                    offset = end
                del block
        finally:
            os.set_blocking(fd, blocking)
