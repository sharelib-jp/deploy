import base64
import contextlib
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

SPEC = importlib.util.spec_from_file_location('prepare', Path(__file__).parents[1] / 'prepare.py')
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PrepareTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.auth_source = self.root / 'auth.toml'
        self.repo_source = self.root / 'repository.toml'
        self.auth_source.write_text('''[METADATA]
NODE_NAME = "図書館"
NODE_ADMINS = [{ name = "admin", email = "admin@example.com" }]
[WEBAUTHN]
RP_DISPLAY_NAME = "図書館の認証"
[BRANDRESOURCES]
HEADER = "resources/custom.svg"
[OAUTH]
SIGNING_KEY_ID = "existing-key-id"
''')
        self.repo_source.write_text('''[OIDC]
ENABLED = false
[EXTERNAL]
SOURCES_FILE = "/app/connectors/custom.yaml"
''')
        example = (prepare.BASE / '.env.example').read_text()
        example = example.replace('auth.example.com', 'auth.library.test').replace('repository.example.com', 'repository.library.test')
        example = example.replace('../auth-service/config.example.toml', 'auth.toml')
        example = example.replace('../repository-service/api/config.example.toml', 'repository.toml')
        (self.root / '.env.example').write_text(example)
        base = patch.object(prepare, 'BASE', self.root)
        base.start()
        self.addCleanup(base.stop)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def run_prepare(self, native=False):
        def create_test_key(args, **_):
            Path(args[-1]).write_text('test key')
        with patch.object(prepare.subprocess, 'run', side_effect=create_test_key) as keygen, \
                patch('sys.argv', ['prepare.py'] + (['--native'] if native else [])), \
                contextlib.redirect_stdout(io.StringIO()):
            prepare.main()
        return keygen.call_count

    def config(self, name):
        return tomllib.loads((self.root / f'runtime/{name}/config.toml').read_text())

    def test_shared_server_and_separate_databases(self):
        (self.root / '.env').write_text("AUTH_POSTGRES_DB=custom_auth\nAUTH_POSTGRES_USER=auth_owner\nAUTH_POSTGRES_PASSWORD='p@ss:/ #$and space'\n")
        self.run_prepare()
        for service, database, user in [('auth', 'custom_auth', 'auth_owner'), ('repository', 'repository', 'repository')]:
            config = self.config(service)
            self.assertEqual(config['DATABASE']['DATABASE_DRIVER'], 'postgres')
            dsn = urlsplit(config['DATABASE']['DATABASE_DSN'])
            self.assertEqual(dsn.hostname, 'postgres')
            self.assertEqual(dsn.port, 5432)
            self.assertEqual(dsn.path, '/' + database)
            self.assertEqual(dsn.username, user)
            if service == 'auth':
                self.assertEqual(unquote(dsn.password), 'p@ss:/ #$and space')
        self.assertEqual(self.config('auth')['OAUTH']['SIGNING_KEY_FILE'], '/app/keys/oidc-signing.pem')

    def test_templates_are_preserved_and_not_modified(self):
        originals = {path: path.read_bytes() for path in [self.auth_source, self.repo_source]}
        self.run_prepare()
        auth = self.config('auth')
        for section in ['METADATA', 'BRANDRESOURCES']:
            self.assertEqual(auth[section], tomllib.loads(self.auth_source.read_text())[section])
        self.assertEqual(auth['WEBAUTHN']['RP_DISPLAY_NAME'], '図書館の認証')
        self.assertEqual(auth['WEBAUTHN']['RP_ORIGIN'], 'https://auth.library.test')
        self.assertEqual(auth['OAUTH']['SIGNING_KEY_ID'], 'existing-key-id')
        self.assertEqual(self.config('repository')['EXTERNAL']['SOURCES_FILE'], '/app/connectors/custom.yaml')
        for path, original in originals.items():
            self.assertEqual(path.read_bytes(), original)

    def test_refresh_registration_matches_oidc_scopes(self):
        for native in [False, True]:
            with self.subTest(native=native):
                self.run_prepare(native)
                client = json.loads((self.root / 'runtime/client.json').read_text())
                config = self.config('repository')['OIDC']
                self.assertIn('refresh_token', client['grant_types'])
                self.assertIn('offline_access', config['SCOPES'])
                self.assertEqual(client['scopes'], config['SCOPES'])
                self.assertEqual(client['redirect_uris'], [config['REDIRECT_URI']])
                self.assertEqual(client['id'], config['CLIENT_ID'])
                self.assertEqual(client['audience'], [])

    def test_custom_client_registration(self):
        self.repo_source.write_text('''[OIDC]
CLIENT_ID = "custom-client"
SCOPES = ["openid", "profile"]
[API_AUTH]
AUDIENCE = "https://repository.library.test/api"
''')
        self.run_prepare()
        client = json.loads((self.root / 'runtime/client.json').read_text())
        self.assertEqual(client['id'], 'custom-client')
        self.assertEqual(client['grant_types'], ['authorization_code'])
        self.assertEqual(client['scopes'], ['openid', 'profile'])
        self.assertEqual(client['audience'], ['https://repository.library.test/api'])

    def test_secrets_and_native_key_are_stable_on_rerun(self):
        self.assertEqual(self.run_prepare(native=True), 1)
        env = (self.root / '.env').read_text()
        configs = {name: self.config(name) for name in ['auth', 'repository']}
        self.assertEqual(self.run_prepare(native=True), 0)
        self.assertEqual((self.root / '.env').read_text(), env)
        self.assertEqual((self.root / '.env').stat().st_mode & 0o777, 0o600)
        values = prepare.read_env(env)
        self.assertEqual(len(base64.urlsafe_b64decode(values['OAUTH_HMAC_SECRET'] + '=')), 32)
        self.assertEqual(len({values[key] for key in values if key.endswith('PASSWORD')}), 3)
        for name, config in configs.items():
            self.assertEqual(self.config(name), config)
            self.assertEqual(config['DATABASE']['DATABASE_DRIVER'], 'sqlite')
            self.assertTrue(config['DATABASE']['DATABASE_DSN'].startswith(str(self.root)))
            self.assertEqual((self.root / f'runtime/{name}/config.toml').stat().st_mode & 0o777, 0o600)

    def test_exported_environment_matches_compose_precedence(self):
        with patch.dict(os.environ, {'AUTH_POSTGRES_DB': 'exported_auth', 'AUTH_POSTGRES_PASSWORD': 'exported-password'}):
            self.run_prepare()
        dsn = urlsplit(self.config('auth')['DATABASE']['DATABASE_DSN'])
        self.assertEqual(dsn.path, '/exported_auth')
        self.assertEqual(dsn.password, 'exported-password')

    def test_invalid_database_and_domain_settings_are_rejected(self):
        for line in ['AUTH_POSTGRES_DB=repository', 'AUTH_POSTGRES_USER=repository',
                     'AUTH_POSTGRES_USER=postgres', 'AUTH_DOMAIN=auth.example.com',
                     'AUTH_DOMAIN=repository.library.test', 'AUTH_DOMAIN=-bad.library.test']:
            with self.subTest(line=line):
                (self.root / '.env').write_text(line + '\n')
                with self.assertRaises(ValueError):
                    self.run_prepare()
                self.assertFalse((self.root / 'runtime').exists())

    def test_missing_template_fails_before_runtime_is_created(self):
        self.repo_source.unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_prepare()
        self.assertFalse((self.root / 'runtime').exists())

    def test_toml_roundtrip_keeps_nested_and_root_settings(self):
        config = {'PORT': ':8080', 'custom section': {'nested': {'quoted.key': ['図書館', True, 42, 1.5]},
                  'created': datetime(2026, 1, 1, tzinfo=timezone.utc)}}
        self.assertEqual(tomllib.loads(prepare.render_config(config)), config)


if __name__ == '__main__':
    unittest.main()
