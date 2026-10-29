"""Run one Rust test with an isolated MIT Kerberos realm and disposable tickets.

Uses krb5kdc/kdb5_util/kadmin.local/kinit from PATH or ZALIVKA_KRB5_RUNTIME.
Does not change system Kerberos files, services or the user's credential cache.
"""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def main():
    runtime = Path(os.environ['ZALIVKA_KRB5_RUNTIME']) if os.environ.get('ZALIVKA_KRB5_RUNTIME') else None
    env = os.environ.copy()
    if runtime:
        libraries = runtime / 'usr/lib/x86_64-linux-gnu'
        env['LD_LIBRARY_PATH'] = str(libraries) + ':' + env.get('LD_LIBRARY_PATH', '')

    def tool(name):
        if runtime:
            for directory in ['usr/sbin', 'usr/bin']:
                for filename in [name, name + '.mit']:
                    candidate = runtime / directory / filename
                    if candidate.exists():
                        return str(candidate)
        result = shutil.which(name)
        if not result:
            raise RuntimeError('Install MIT Kerberos test tools or set ZALIVKA_KRB5_RUNTIME: ' + name)
        return result

    with tempfile.TemporaryDirectory(prefix='zalivka-kerberos-') as temporary:
        directory = Path(temporary)
        config = directory / 'krb5.conf'
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        plugin = ''
        if runtime:
            plugin = f' db_module_dir = {runtime}/usr/lib/x86_64-linux-gnu/krb5/plugins/kdb\n'
        config.write_text(f'''[libdefaults]
 default_realm = ZALIVKA.TEST
 dns_lookup_realm = false
 dns_lookup_kdc = false
 dns_canonicalize_hostname = false
 rdns = false
 default_ccache_name = FILE:{directory}/ccache
[realms]
 ZALIVKA.TEST = {{
  kdc = 127.0.0.1:{port}
  database_module = fixture
  key_stash_file = {directory}/stash
 }}
[domain_realm]
 127.0.0.1 = ZALIVKA.TEST
[dbmodules]
{plugin} fixture = {{
  db_library = db2
  database_name = {directory}/principal
 }}
[kdcdefaults]
 kdc_listen = 127.0.0.1:{port}
 kdc_tcp_listen = 127.0.0.1:{port}
[logging]
 kdc = FILE:{directory}/kdc.log
''')
        env.update(KRB5_CONFIG=str(config), KRB5_KDC_PROFILE=str(config),
                   KRB5CCNAME='FILE:' + str(directory / 'ccache'),
                   KRB5_KTNAME='FILE:' + str(directory / 'service.keytab'))

        def run(arguments, **kwargs):
            result = subprocess.run(arguments, env=env, text=True, capture_output=True, **kwargs)
            if result.returncode:
                raise RuntimeError(f'{Path(arguments[0]).name}: {result.stdout}\n{result.stderr}')
            return result

        run([tool('kdb5_util'), 'create', '-s', '-P', 'fixture-master-only', '-r', 'ZALIVKA.TEST'])
        run([tool('kadmin.local'), '-r', 'ZALIVKA.TEST', '-q', 'addprinc -pw fixture-password-only fixture-user'])
        run([tool('kadmin.local'), '-r', 'ZALIVKA.TEST', '-q', 'addprinc -randkey HTTP/127.0.0.1'])
        run([tool('kadmin.local'), '-r', 'ZALIVKA.TEST', '-q', f'ktadd -k {directory}/service.keytab HTTP/127.0.0.1'])
        with (directory / 'kdc-process.log').open('w') as log:
            kdc = subprocess.Popen([tool('krb5kdc'), '-n', '-r', 'ZALIVKA.TEST', '-P', str(directory / 'kdc.pid')], env=env, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if kdc.poll() is not None:
                        raise RuntimeError(f'KDC exited {kdc.returncode}: ' + (directory / 'kdc-process.log').read_text() + ((directory / 'kdc.log').read_text() if (directory / 'kdc.log').exists() else ''))
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError('temporary KDC did not start')
                run([tool('kinit'), 'fixture-user@ZALIVKA.TEST'], input='fixture-password-only\n')
                env['ZALIVKA_KERBEROS_READY'] = '1'
                result = subprocess.run([os.environ['ZALIVKA_KERBEROS_TEST_BIN'], os.environ['ZALIVKA_KERBEROS_TEST_NAME'], '--exact', '--ignored', '--nocapture'], env=env)
                return result.returncode
            finally:
                kdc.terminate()
                try:
                    kdc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    kdc.kill()
                    kdc.wait()


if __name__ == '__main__':
    sys.exit(main())
