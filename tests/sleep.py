from river import River
import os

def main():
    r = River("sleep 3")
    resp = r.run()
    print(resp.time_used, resp.memory_used, resp.exit_code, resp.signal)

main()
