import river

with river.Sandbox(rootfs="/path/to/rootfs") as sandbox:
    print(sandbox)
    r = sandbox.run("/path/to/executable")
    print(r)
    print(r.time_used, r.memory_used, r.wall_time_used)
    print(r.status, r.signal, r.exit_code)
    print(r.stdout, r.stderr)
