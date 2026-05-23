/**
 * Run every scenario in this folder, show each one's output, and end
 * with a summary table. Exit code is 0 if every scenario passed, 1 if
 * any failed.
 *
 * Usage:
 *
 *   node dist/run_all.js              # run every tier
 *   node dist/run_all.js --tier 1     # run only tier 1
 *   node dist/run_all.js --only 05    # run scripts whose filename contains 05
 */

import { spawnSync } from 'child_process';
import { readdirSync, statSync } from 'fs';
import { join, resolve } from 'path';

const HERE = resolve(__dirname);

function parseArgs(): { tier: number | null; only: string | null } {
  const argv = process.argv.slice(2);
  let tier: number | null = null;
  let only: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--tier') {
      const next = argv[i + 1];
      if (next !== undefined) {
        tier = parseInt(next, 10);
        i++;
      }
    } else if (a === '--only') {
      const next = argv[i + 1];
      if (next !== undefined) {
        only = next;
        i++;
      }
    }
  }
  return { tier, only };
}

function discover(tier: number | null, only: string | null): string[] {
  const allEntries = readdirSync(HERE);
  let tierDirs = allEntries
    .filter(name => name.startsWith('tier'))
    .map(name => join(HERE, name))
    .filter(path => {
      try {
        return statSync(path).isDirectory();
      } catch {
        return false;
      }
    })
    .sort();
  if (tier !== null) {
    tierDirs = tierDirs.filter(d => d.endsWith(`tier${tier}`));
  }

  const scripts: string[] = [];
  for (const td of tierDirs) {
    const files = readdirSync(td)
      .filter(f => f.endsWith('.js'))
      .filter(f => !f.startsWith('_') && !f.startsWith('.'))
      .sort();
    for (const f of files) {
      if (only && !f.includes(only)) continue;
      scripts.push(join(td, f));
    }
  }
  return scripts;
}

function rel(path: string): string {
  return path.startsWith(HERE) ? path.slice(HERE.length + 1) : path;
}

function main(): number {
  const { tier, only } = parseArgs();
  const scripts = discover(tier, only);
  if (scripts.length === 0) {
    console.log('No scenarios matched. Nothing to run.');
    return 0;
  }

  const bar = '='.repeat(72);
  console.log(bar);
  console.log(`Running ${scripts.length} scenario(s)`);
  if (tier !== null) console.log(`  tier filter   : tier ${tier}`);
  if (only) console.log(`  substring filter: '${only}'`);
  console.log(bar);

  const results: { script: string; ok: boolean; elapsed: number }[] = [];
  for (const script of scripts) {
    console.log();
    console.log(bar);
    console.log(`> ${rel(script)}`);
    console.log(bar);
    const start = Date.now();
    const r = spawnSync(process.execPath, [script], { stdio: 'inherit', cwd: HERE });
    const elapsed = (Date.now() - start) / 1000;
    results.push({ script, ok: r.status === 0, elapsed });
  }

  console.log();
  console.log(bar);
  console.log('Summary');
  console.log(bar);
  for (const { script, ok, elapsed } of results) {
    const mark = ok ? 'PASS' : 'FAIL';
    const r = rel(script).padEnd(54);
    console.log(`  [${mark}] ${r} ${elapsed.toFixed(2).padStart(6)}s`);
  }
  console.log(bar);

  const passed = results.filter(r => r.ok).length;
  const total = results.length;
  const totalTime = results.reduce((acc, r) => acc + r.elapsed, 0);
  if (passed === total) {
    console.log(`${passed}/${total} scenarios passed in ${totalTime.toFixed(2)}s`);
  } else {
    const failing = total - passed;
    console.log(`${passed}/${total} scenarios passed, ${failing} FAILED, total ${totalTime.toFixed(2)}s`);
  }
  console.log(bar);

  return passed === total ? 0 : 1;
}

process.exit(main());
