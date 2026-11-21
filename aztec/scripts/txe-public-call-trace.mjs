// Test-only observation of the real transaction passed to the public processor.
// Do not replace execution, construct requests, or infer calls from final effects.
import { AsyncLocalStorage } from 'node:async_hooks';

export function installPublicCallTrace(TXESession, PublicProcessor, toSingle) {
  const active = new AsyncLocalStorage();
  const traces = new WeakMap();
  const execute = TXESession.prototype.executePrivateCall;
  const process = PublicProcessor.prototype.process;
  const oracle = TXESession.prototype.processFunction;

  PublicProcessor.prototype.process = async function (transactions, ...args) {
    const trace = active.getStore();
    if (trace) {
      if (trace.calls !== undefined || !Array.isArray(transactions) || transactions.length !== 1) {
        throw new Error('Expected exactly one TXE transaction for public-call tracing');
      }
      trace.calls = transactions[0].getPublicCallRequestsWithCalldata();
      if (trace.calls.some(call => call.calldata.length === 0)) {
        throw new Error('Public-call trace is missing a calldata preimage');
      }
    }
    return process.call(this, transactions, ...args);
  };

  TXESession.prototype.executePrivateCall = async function (...args) {
    // Invalidate the previous result even if this execution fails. A missing
    // observation must never look like an observed empty request list.
    traces.delete(this);
    const trace = {};
    return active.run(trace, async () => {
      const result = await execute.apply(this, args);
      if (trace.calls === undefined) {
        throw new Error('TXE public-call trace was not observed');
      }
      traces.set(this, trace.calls);
      return result;
    });
  };

  TXESession.prototype.processFunction = async function (name, inputs) {
    if (name !== 'zka_txe_publicCallCount' && name !== 'zka_txe_publicCall') {
      // Public/utility calls may replace the last call; never expose a stale
      // private trace after one of them. Trace queries themselves are read-only.
      traces.delete(this);
      return oracle.call(this, name, inputs);
    }
    const calls = traces.get(this);
    if (calls === undefined) {
      throw new Error('No successfully observed private call for public-call trace');
    }
    if (name === 'zka_txe_publicCallCount') {
      if (inputs.length !== 0) throw new Error('publicCallCount takes no arguments');
      return { values: [toSingle(calls.length)] };
    }
    if (inputs.length !== 2 || inputs.some(value => typeof value !== 'string')) {
      throw new Error('publicCall expects index and exact calldata length');
    }
    const [index, length] = inputs.map(value => BigInt(`0x${value.replace(/^0x/, '')}`));
    if (index >= BigInt(calls.length)) throw new Error('Public-call trace index out of range');
    const { request, calldata } = calls[Number(index)];
    if (length !== BigInt(calldata.length)) throw new Error('Public-call trace calldata length mismatch');
    return {
      values: [
        toSingle(request.msgSender), toSingle(request.contractAddress), toSingle(request.isStaticCall),
        calldata.map(toSingle),
      ],
    };
  };
}
