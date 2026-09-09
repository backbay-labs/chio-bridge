import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
const artifact = resolve(process.argv[2]);
const directory = mkdtempSync(join(tmpdir(), 'chio-packaged-cli-symlink-'));
const consumer = join(directory, 'consumer'); mkdirSync(consumer);
writeFileSync(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
const install = spawnSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', join(directory, 'empty-cache'), '--registry=http://127.0.0.1:9', artifact], { cwd: consumer, encoding: 'utf8', timeout: 30000 });
assert.equal(install.status, 0, install.stderr);
const alias = join(directory, 'symlink-parent'); symlinkSync(realpathSync(consumer), alias, 'dir');
const configPath = join(directory, 'config.json');
writeFileSync(configPath, JSON.stringify({ execution: { endpoint: 'http://127.0.0.1:1', bearerToken: 'discovery-only-test', trustedSigners: ['aa'.repeat(32)], subjectKey: 'bb'.repeat(32), capabilityId: 'test-cap', serverId: 'fs', sessionId: 'kernel-session' }, sessionId: 'host-session', journalDir: join(directory, 'journal'), tools: [{ name: 'read_file', inputSchema: { type: 'object' } }] }), { mode: 0o600 });
chmodSync(directory, 0o700);
const input = [{ jsonrpc: '2.0', id: 1, method: 'initialize' }, { jsonrpc: '2.0', method: 'notifications/initialized' }, { jsonrpc: '2.0', id: 2, method: 'tools/list' }].map(v => JSON.stringify(v)).join('\n') + '\n';
const rows = [];
for (const entry of ['node_modules/@chio/bridge/dist/gateway.js', 'node_modules/.bin/chio-mcp-gateway']) {
  for (const flags of [[], ['--preserve-symlinks-main']]) {
    const run = spawnSync(process.execPath, [...flags, join(alias, entry), configPath], { input, encoding: 'utf8', timeout: 10000 });
    assert.equal(run.error, undefined);
    if (entry.includes('/.bin/') && flags.length) {
      assert.equal(run.status, 1); assert.match(run.stderr, /ERR_MODULE_NOT_FOUND/);
      rows.push({ entry, flags, exit: run.status, status: 'unsupported Node flag combination: bin symlink is preserved so relative and nested package imports resolve from .bin', protectedCalls: 0 });
      continue;
    }
    assert.equal(run.status, 0, run.stderr);
    const replies = run.stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    assert.equal(replies.length, 2, 'packaged CLI must respond through a symlinked parent');
    assert.equal(replies[0].result.serverInfo.name, 'chio-mcp-gateway');
    assert.equal(replies[1].result.tools[0].name, 'read_file');
    rows.push({ entry, flags, exit: run.status, replies });
  }
}
console.log(JSON.stringify({ artifact, sha256: createHash('sha256').update(readFileSync(artifact)).digest('hex'), consumer, alias, offline: true, emptyCache: true, registry: 'http://127.0.0.1:9', protectedCalls: 0, cases: rows }, null, 2));
