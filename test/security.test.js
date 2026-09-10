import { assert } from 'chai';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Util } from '../lib/util/util.js';
import jsonToTable from '../lib/util/jsonToTable.js';
import {
    isSafeGitRemote,
    protectCredentialFile,
    redactSecrets,
    writeCredentials,
} from '../lib/util/security.js';

describe('Security regression tests', () => {
    let directory;

    beforeEach(() => {
        directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mcdev-security-'));
    });

    afterEach(() => {
        fs.rmSync(directory, { recursive: true, force: true });
    });

    it('passes shell metacharacters, quotes and spaces as literal arguments', () => {
        const marker = path.join(directory, 'unexpected');
        const values = [
            'Jane Smith',
            'Initial commit',
            'type=module',
            `$(touch ${marker})`,
            `;touch ${marker}`,
            '`touch unexpected`',
            'a"b',
        ];
        const output = Util.execSync(
            process.execPath,
            ['-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', '--', ...values],
            true
        );
        assert.isString(output);
        assert.deepEqual(JSON.parse(/** @type {string} */ (output)), values);
        assert.isFalse(fs.existsSync(marker));
    });

    it('preserves Git user names and commit messages without shell quoting', () => {
        Util.execSync('git', ['init', '--quiet', directory], true);
        const name = 'Dana "Example" User';
        Util.execSync('git', ['-C', directory, 'config', 'user.name', name], true);
        Util.execSync(
            'git',
            ['-C', directory, 'config', 'user.email', 'test@example.invalid'],
            true
        );
        Util.execSync(
            'git',
            ['-C', directory, 'commit', '--allow-empty', '-m', 'Initial commit', '--quiet'],
            true
        );
        assert.equal(
            Util.execSync('git', ['-C', directory, 'log', '-1', '--format=%an|%s'], true),
            `${name}|Initial commit`
        );
    });

    it('rejects executable Git transports and option-like remote input', () => {
        for (const value of [
            'ext::sh -c anything',
            '--config=protocol.ext.allow=always',
            'file:///tmp/repo',
            'http://example.com/repo.git',
            'https://user:secret@example.com/repo.git',
            'https://example.com/repo.git\n--config=x',
        ]) {
            assert.isFalse(isSafeGitRemote(value), value);
        }
        for (const value of [
            'https://github.com/brandlogic/sfmc-devtools.git',
            'ssh://git@github.com/brandlogic/sfmc-devtools.git',
            'git@github.com:brandlogic/sfmc-devtools.git',
        ]) {
            assert.isTrue(isSafeGitRemote(value), value);
        }
    });

    it('preserves report headers, missing values, booleans and nested fields', () => {
        assert.deepEqual(
            jsonToTable([
                { Name: 'A', IsRequired: false, nested: { value: 0 } },
                { Name: 'B', IsRequired: true, extra: null },
            ]),
            [
                ['Name', 'IsRequired', 'nested.value', 'extra'],
                ['A', false, 0, ''],
                ['B', true, '', null],
            ]
        );
        assert.deepEqual(jsonToTable([]), [[]]);
    });

    it('handles prototype-related and dotted keys without interpreting inherited paths', () => {
        const row = JSON.parse(
            '{"__proto__":{"polluted":"value"},"nested":{"a.b":7},"constructor":"own"}'
        );
        assert.deepEqual(jsonToTable([row]), [
            ['__proto__.polluted', 'nested.`a.b`', 'constructor'],
            ['value', 7, 'own'],
        ]);
        assert.isUndefined({}.polluted);
        assert.deepEqual(jsonToTable([Object.create({ secret: 'inherited' })]), [[], []]);
    });

    it('redacts mixed-case headers and nested tokens without mutating API data', () => {
        const original = {
            headers: { authorization: 'Bearer secret', 'Set-Cookie': 'secret' },
            data: { client_secret: 'secret', nested: [{ access_token: 'secret' }], name: 'keep' },
        };
        const redacted = redactSecrets(original);
        assert.notInclude(JSON.stringify(redacted), '"secret"');
        assert.equal(redacted.data.name, 'keep');
        assert.equal(original.data.client_secret, 'secret');
        assert.equal(original.headers.authorization, 'Bearer secret');
    });

    it('redacts JSON, multiline namespaced SOAP tokens and form-encoded credentials', () => {
        for (const value of [
            '{"access_token":"topsecret","clientSecret":"topsecret"}',
            '<s:fueloauth xmlns:s="urn:test">\ntopsecret\n</s:fueloauth>',
            'client_secret=topsecret&name=keep',
            'https://example.invalid/?access_token=topsecret&name=keep',
            'Bearer topsecret',
        ]) {
            assert.notInclude(redactSecrets(value), 'topsecret');
        }
    });

    it('creates and updates credential files with owner-only permissions', async () => {
        const filename = path.join(directory, '.mcdev-auth.json');
        await writeCredentials(filename, { client_secret: 'old value' });
        if (process.platform !== 'win32') {
            assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
            fs.chmodSync(filename, 0o644);
        }
        await writeCredentials(filename, { client_secret: 'new' });
        assert.deepEqual(JSON.parse(fs.readFileSync(filename, 'utf8')), { client_secret: 'new' });
        if (process.platform !== 'win32') {
            assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
        }
    });

    it('rejects symlink credential files without overwriting their targets', async function () {
        if (process.platform === 'win32') {
            this.skip();
        }
        const target = path.join(directory, 'target.json');
        const link = path.join(directory, '.mcdev-auth.json');
        fs.writeFileSync(target, 'unchanged');
        fs.symlinkSync(target, link);
        assert.throws(() => protectCredentialFile(link), /regular file/);
        try {
            await writeCredentials(link, { secret: 'new' });
            assert.fail('symlink must not be writable');
        } catch (ex) {
            assert.match(ex.message, /regular file/);
        }
        assert.equal(fs.readFileSync(target, 'utf8'), 'unchanged');
    });
});
