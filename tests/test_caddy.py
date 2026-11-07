"""Check the effective gateway protocol without running a server or issuing certificates."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class CaddyTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which('caddy'), 'caddy is not installed')
    def test_tunnel_origin_serves_http_without_tls_or_https_redirects(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            fragment = folder / 'active.caddy'
            fragment.write_text('')
            caddyfile = folder / 'Caddyfile'
            caddyfile.write_text((root / 'Caddyfile').read_text().replace(
                '/srv/main/control/active.caddy', str(fragment)))
            env = os.environ.copy()
            domains = ['auth.library.test', 'repository.library.test', 'catalog.library.test']
            env.update(zip(['AUTH_DOMAIN', 'REPOSITORY_DOMAIN', 'MAIN_DOMAIN'], domains))
            result = subprocess.run(['caddy', 'adapt', '--config', str(caddyfile), '--adapter', 'caddyfile'],
                                    env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        self.assertNotIn('tls', config['apps'])
        servers = config['apps']['http']['servers'].values()
        hosts = set()
        for server in servers:
            self.assertEqual(server['listen'], [':80'])
            self.assertNotIn('tls_connection_policies', server)
            for route in server['routes']:
                for match in route.get('match', []):
                    hosts.update(match.get('host', []))
        self.assertEqual(hosts, set(domains))
