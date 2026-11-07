"""Validate rendered Compose networking and optional services, without starting them."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


class ComposeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('docker'):
            raise unittest.SkipTest('docker compose is not installed')
        result = subprocess.run(['docker', 'compose', 'version'], capture_output=True, text=True)
        if result.returncode:
            raise unittest.SkipTest('docker compose is not available')
        cls.root = Path(__file__).resolve().parents[1]

    def config(self, *profiles):
        env = os.environ.copy()
        env.pop('COMPOSE_PROFILES', None)
        env.update({name: 'test-only-credential-with-at-least-32-bytes' for name in [
            'POSTGRES_PASSWORD', 'AUTH_POSTGRES_PASSWORD', 'REPOSITORY_POSTGRES_PASSWORD',
            'PGADMIN_DEFAULT_PASSWORD', 'CATALOG_API_TOKEN']})
        env.update(AUTH_DOMAIN='auth.library.test', REPOSITORY_DOMAIN='repository.library.test',
                   MAIN_DOMAIN='catalog.library.test', PGADMIN_DEFAULT_EMAIL='admin@example.com',
                   PGADMIN_BIND_ADDRESS='127.0.0.1', PGADMIN_PORT='5050',
                   CLOUDFLARE_TUNNEL_TOKEN='test-token-not-used-for-a-connection')
        args = ['docker', 'compose', '--env-file', '/dev/null', '-f', str(self.root / 'compose.yaml')]
        for profile in profiles:
            args += ['--profile', profile]
        result = subprocess.run(args + ['config', '--format', 'json'], env=env, cwd=self.root,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_optional_services_do_not_start_by_default(self):
        config = self.config()
        self.assertNotIn('cloudflared', config['services'])
        self.assertNotIn('pgadmin', config['services'])
        self.assertIn('main', config['services'])

    def test_database_is_private_and_service_dns_is_shared(self):
        config = self.config('*')
        self.assertTrue(config['networks']['database']['internal'])
        self.assertFalse(config['networks']['app'].get('internal', False))
        postgres = config['services']['postgres']
        self.assertFalse(postgres.get('ports'))
        self.assertEqual(set(postgres['networks']), {'database'})
        for name in ['auth', 'repository', 'pgadmin']:
            self.assertEqual(set(config['services'][name]['networks']), {'app', 'database'})
        for name in ['main', 'gateway', 'cloudflared']:
            self.assertEqual(set(config['services'][name]['networks']), {'app'})
        gateway = config['services']['gateway']
        self.assertFalse(gateway.get('ports'))
        network = gateway['networks']['app'] or {}
        self.assertTrue(set(network.get('aliases', [])).isdisjoint({
            'auth.library.test', 'repository.library.test', 'catalog.library.test'}))

    def test_pgadmin_login_persistence_and_local_binding(self):
        config = self.config('admin')
        self.assertNotIn('cloudflared', config['services'])
        service = config['services']['pgadmin']
        port = service['ports'][0]
        self.assertEqual(port['host_ip'], '127.0.0.1')
        self.assertEqual(str(port['published']), '5050')
        self.assertEqual(port['target'], 80)
        self.assertTrue(service['environment']['PGADMIN_DEFAULT_PASSWORD'])
        definitions = next(v for v in service['volumes'] if v['target'] == '/pgadmin4/servers.json')
        self.assertTrue(definitions['read_only'])
        self.assertTrue(definitions['source'].endswith('/runtime/pgadmin/servers.json'))
        self.assertTrue(any(v['target'] == '/var/lib/pgadmin' and v['type'] == 'volume'
                            for v in service['volumes']))

    def test_tunnel_uses_service_network_and_token_environment(self):
        config = self.config('tunnel')
        self.assertNotIn('pgadmin', config['services'])
        service = config['services']['cloudflared']
        self.assertEqual(service['command'], ['tunnel', '--no-autoupdate', 'run'])
        self.assertEqual(service['environment']['TUNNEL_TOKEN'], 'test-token-not-used-for-a-connection')
        self.assertFalse(service.get('ports'))
        self.assertFalse(service.get('volumes'))
        self.assertNotIn('test-token-not-used-for-a-connection', service['command'])
