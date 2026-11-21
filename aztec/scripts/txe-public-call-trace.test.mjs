import assert from 'node:assert/strict';
import test from 'node:test';
import { installPublicCallTrace } from './txe-public-call-trace.mjs';

const field = value => BigInt(value).toString(16).padStart(64, '0');
const request = (...calldata) => ({
  request: { msgSender: 11, contractAddress: 22, isStaticCall: false }, calldata,
});

function fixture() {
  class Processor {
    async process(txs) { return txs; }
  }
  class Session {
    async executePrivateCall(calls, options = {}) {
      if (options.wait) await options.wait;
      if (options.skip) return 'not observed';
      const tx = { getPublicCallRequestsWithCalldata: () => calls };
      await new Processor().process([tx]);
      if (options.fail) throw new Error('execution failed');
      return 'executed';
    }
    async processFunction(name, inputs) {
      if (name === 'execute') return this.executePrivateCall(...inputs);
      return { forwarded: name };
    }
  }
  installPublicCallTrace(Session, Processor, field);
  return { Session, Processor };
}

const count = session => session.processFunction('zka_txe_publicCallCount', []);
const call = (session, index, length) =>
  session.processFunction('zka_txe_publicCall', [field(index), field(length)]);

test('returns the observed sender, target, staticness, selector and exact arguments', async () => {
  const { Session } = fixture();
  const session = new Session();
  assert.equal(await session.processFunction('execute', [[request(123, 456)]]), 'executed');
  assert.deepEqual(await count(session), { values: [field(1)] });
  assert.deepEqual(await call(session, 0, 2), {
    values: [field(11), field(22), field(false), [field(123), field(456)]],
  });
  // A leaked holder anchor is preserved, never truncated to owner-only calldata.
  await session.processFunction('execute', [[request(123, 456, 789)]]);
  await assert.rejects(call(session, 0, 2), /calldata length mismatch/);
  assert.deepEqual((await call(session, 0, 3)).values[3], [123, 456, 789].map(field));
});

test('includes every request supplied by the transaction, including nested and teardown entries', async () => {
  const { Session } = fixture();
  const session = new Session();
  await session.processFunction('execute', [[request(1, 2), request(3, 4), request(5, 6)]]);
  assert.deepEqual(await count(session), { values: [field(3)] });
  assert.deepEqual((await call(session, 2, 2)).values[3], [field(5), field(6)]);
  await assert.rejects(call(session, 3, 2), /index out of range/);
});

test('distinguishes a real empty trace from unobserved or failed execution', async () => {
  const { Session } = fixture();
  const session = new Session();
  await assert.rejects(count(session), /No successfully observed/);
  await session.processFunction('execute', [[]]);
  assert.deepEqual(await count(session), { values: [field(0)] });
  await assert.rejects(session.processFunction('execute', [[], { skip: true }]), /not observed/);
  await assert.rejects(count(session), /No successfully observed/);
  await session.processFunction('execute', [[request(1)]]);
  await assert.rejects(session.processFunction('execute', [[], { fail: true }]), /execution failed/);
  await assert.rejects(count(session), /No successfully observed/);
});

test('rejects missing calldata and malformed oracle queries', async () => {
  const { Session } = fixture();
  const session = new Session();
  await assert.rejects(session.processFunction('execute', [[request()]]), /missing a calldata preimage/);
  await assert.rejects(count(session), /No successfully observed/);
  await session.processFunction('execute', [[request(1)]]);
  await assert.rejects(session.processFunction('zka_txe_publicCallCount', [field(0)]), /no arguments/);
  await assert.rejects(session.processFunction('zka_txe_publicCall', []), /expects index/);
});

test('invalidates a private trace on other oracle calls and forwards those unchanged', async () => {
  const { Session } = fixture();
  const session = new Session();
  await session.processFunction('execute', [[request(1)]]);
  assert.deepEqual(await session.processFunction('viewPublic', []), { forwarded: 'viewPublic' });
  await assert.rejects(count(session), /No successfully observed/);
});

test('keeps interleaved sessions isolated and leaves unrelated processing untouched', async () => {
  const { Session, Processor } = fixture();
  const first = new Session();
  const second = new Session();
  let release;
  const wait = new Promise(resolve => { release = resolve; });
  const pending = first.processFunction('execute', [[request(111)], { wait }]);
  await second.processFunction('execute', [[request(222)]]);
  release();
  await pending;
  assert.deepEqual((await call(first, 0, 1)).values[3], [field(111)]);
  assert.deepEqual((await call(second, 0, 1)).values[3], [field(222)]);
  assert.deepEqual(await new Processor().process(['unrelated']), ['unrelated']);
});
