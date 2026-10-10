"""
Container entrypoint: start as root just long enough to make /data writable, then drop to
PUID:PGID (default 99:100, Unraid's nobody:users) and exec the real command.

Running the dashboard unprivileged limits the damage if it's ever compromised. PUID=0 keeps
the old run-as-root behaviour, e.g. if the NPM log files are only readable by root.
"""
import os
import sys

DATA = os.environ.get("DATA_DIR", "/data")


def main():
    uid = int(os.environ.get("PUID", "99"))
    gid = int(os.environ.get("PGID", "100"))
    if os.getuid() == 0 and uid != 0:
        os.makedirs(DATA, exist_ok=True)
        # earlier versions ran as root, so an existing dash.db is root-owned
        for root, dirs, files in os.walk(DATA):
            for name in [root] + [os.path.join(root, n) for n in dirs + files]:
                os.lchown(name, uid, gid)
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
