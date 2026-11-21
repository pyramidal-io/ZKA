// Use the pinned, installed TXE without changing its files. Its Noir API does
// not expose enqueued requests, so add two read-only test oracles locally.
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { createRequire, registerHooks } from 'node:module';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { installPublicCallTrace } from './txe-public-call-trace.mjs';

const [aztecBin, port] = process.argv.slice(2);
if (!aztecBin || !/^\d+$/.test(port ?? '') || Number(port) < 1 || Number(port) > 65535) {
  throw new Error('usage: txe-trace-server.mjs <aztec executable> <port>');
}
// Set before loading TXE/native state, matching the pinned TXE launcher.
process.env.HARDWARE_CONCURRENCY ??= '2';
process.env.TXE_WORKERS = '1'; // The observer and executor must share class instances.
const requireAztec = createRequire(realpathSync(aztecBin));
const roots = requireAztec.resolve.paths('@aztec-labs/txe');
const root = roots?.find(dir => existsSync(join(dir, '@aztec-labs/txe/package.json')));
if (!root) throw new Error('Cannot locate the installed pinned TXE beside aztec');
const txe = join(root, '@aztec-labs/txe');
if (JSON.parse(readFileSync(join(txe, 'package.json'), 'utf8')).version !== '6.0.0') {
  throw new Error('Public-call trace adapter requires TXE 6.0.0');
}
// The installed unbundled TXE modules import their shipped artifact JSON without
// attributes (the standard launcher bundles those imports). Preserve native JSON
// parsing while supplying the attribute for files within this installed tree.
const packagePrefix = pathToFileURL(`${realpathSync(root)}/`).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context);
    return resolved.url.startsWith(packagePrefix) && resolved.url.endsWith('.json')
      ? { ...resolved, importAttributes: { type: 'json' } } : resolved;
  },
});
const load = relative => import(pathToFileURL(join(txe, 'dest', relative)).href);
const [{ TXESession }, { toSingle }, { PublicProcessor }] = await Promise.all([
  load('txe_session.js'), load('utils/encoding.js'),
  import(pathToFileURL(requireAztec.resolve('@aztec-labs/simulator/server')).href),
]);
installPublicCallTrace(TXESession, PublicProcessor, toSingle);
const [{ createTXERpcServer }, { startHttpRpcServer }, { createLogger }] = await Promise.all([
  load('rpc_server.js'),
  import(pathToFileURL(requireAztec.resolve('@aztec-labs/foundation/json-rpc/server')).href),
  import(pathToFileURL(requireAztec.resolve('@aztec-labs/foundation/log')).href),
]);
const logger = createLogger('zka:txe-public-calls');
await startHttpRpcServer(await createTXERpcServer(logger), {
  host: '127.0.0.1', port: Number(port), timeoutMs: 300_000,
});
logger.info(`TXE public-call trace server listening on ${port}`);
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => process.exit(0));
