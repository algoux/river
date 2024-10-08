from river import River
import os

def main():
    r = River("echo Hello         World!")
    r.time_limit = 1000
    r.memory_limit = 65535
    r.out_fd = 1
    r.err_fd = 2
    print(r)
    resp = r.run()
    print(resp.time_used, resp.memory_used, resp.exit_code, resp.signal)

main()
