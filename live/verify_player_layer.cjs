#!/usr/bin/env node
'use strict';
// Optional analysis helper for this exact uploaded player bundle.
// Usage: node verify_player_layer.cjs liveplayer_controls.js validation_vectors.json
// Node.js 18+; no npm packages. Not needed for TS decryption.
const fs = require('fs');
const vm = require('vm');
const crypto = require('crypto');
const assert = require('assert/strict');

function main() {
  const [controlsPath, vectorsPath] = process.argv.slice(2);
  if (!controlsPath || !vectorsPath) {
    throw new Error('Usage: node verify_player_layer.cjs liveplayer_controls.js validation_vectors.json');
  }
  const bytes = fs.readFileSync(controlsPath);
  const expectedHash = '5d2194022dc6b59da24cdae1b95af30df436a64a10e157ee6e19137ac90fe94b';
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), expectedHash,
    'This helper is pinned to the analyzed player version');
  const source = bytes.toString('utf8');
  const banner = '/*2026-08-25 17:37:12';
  const begin = source.indexOf(banner);
  assert(begin >= 0, 'HLS bundle banner missing');
  let hlsSource = source.slice(begin);
  const marker = 'return wm(),Lm}';
  assert.equal(hlsSource.split(marker).length, 2, 'Factory exit marker must be unique');
  // Expose the existing function; omit only the final wm() self-defense check.
  // No TEA, name-mask or HLS media transformation body is rewritten here.
  hlsSource = hlsSource.replace(marker,
    'globalThis.__analysis={postprocess:Qu,bridge:Ja,Hls:Lm};return Lm}');
  const quiet = { log() {}, debug() {}, warn() {}, error() {} };
  const globals = {
    console: quiet, navigator: { userAgent: 'Mozilla/5.0' }, document: {},
    setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {},
    URL, TextDecoder, TextEncoder, Uint8Array, ArrayBuffer,
  };
  globals.window = globals;
  globals.self = globals;
  const context = vm.createContext(globals);
  vm.runInContext(hlsSource, context, { timeout: 10000 });
  assert(context.__analysis, 'Analysis export not created');
  const fixture = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
  const results = [];
  for (const vector of fixture.vectors) {
    context.__vectorInput = Uint8Array.from(Buffer.from(vector.wasm_output_hex, 'hex'));
    context.__vectorName = fixture.test_identifier;
    const result = vm.runInContext(
      '__analysis.postprocess(__vectorInput,__vectorName)', context, { timeout: 2000 });
    assert.equal(Buffer.from(result).toString('hex'), vector.final_output_hex,
      'JS postprocessing mismatch: ' + vector.label);
    results.push({ label: vector.label, bytes: result.length, matched: true });
  }
  // Observe the origin of the initialization identifier with a fake element.
  context.__mediaProbe = { config: {}, logger: { log() {} }, trigger() {} };
  vm.runInContext(
    '__analysis.Hls.prototype.attachMedia.call(__mediaProbe,{id:"probeVideoId"})',
    context, { timeout: 2000 });
  assert.equal(context.__mediaProbe.config.mediaTagId, 'probeVideoId');
  console.log(JSON.stringify({
    controls_sha256: expectedHash,
    initialization_identifier_source: 'media.id (fallback: String(Date.now()))',
    postprocess_function: 'Qu', vectors: results,
    note: 'Fixture WASM outputs were recorded in the earlier instrumented WASM run; this helper re-executes the original JS postprocessor.',
  }, null, 2));
}

try { main(); }
catch (error) {
  console.error('ERROR: ' + error.message);
  process.exitCode = 1;
}
