"""`opsdir-api`: the API served by uvicorn on OPSDIR_API_HOST:OPSDIR_API_PORT (default 127.0.0.1:8080), plain HTTP
for a TLS-terminating reverse proxy in front of it; refused, naming each problem, while the configuration has any."""
import os
import sys

from .app import create_app
from .config import config_from, listen_from


def main(env=None):
    """Effect: serve the API until stopped; exit naming the configuration's problems when it has any."""
    env = os.environ if env is None else env
    config, problems = config_from(env)
    listen, listen_problems = listen_from(env)
    if problems or listen_problems:
        sys.exit("opsdir-api: not started:\n" + "\n".join(f"  {p}" for p in (*problems, *listen_problems)))
    import uvicorn
    uvicorn.run(create_app(config), host=listen.host, port=listen.port, proxy_headers=True,
                forwarded_allow_ips=env.get("OPSDIR_API_FORWARDED_ALLOW_IPS", "127.0.0.1"))


if __name__ == "__main__":
    main()
