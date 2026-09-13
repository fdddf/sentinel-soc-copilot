import * as esbuild from 'esbuild';
import { cpSync, mkdirSync } from 'node:fs';

const watch = process.argv.includes('--watch');
mkdirSync('dist/assets', { recursive: true });
cpSync('index.html', 'dist/index.html');

const ctx = await esbuild.context({
  entryPoints: { main: 'src/main.js' },
  bundle: true,
  format: 'esm',
  minify: !watch,
  sourcemap: watch,
  outdir: 'dist/assets',
  logLevel: 'info',
});
if (watch) await ctx.watch();
else { await ctx.rebuild(); await ctx.dispose(); }
