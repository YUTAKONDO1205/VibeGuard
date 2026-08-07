#!/usr/bin/env node
// vgcc — the C driver. Wraps clang-18.
import { cli } from './main.mjs';

await cli({ driverName: 'vgcc', mode: 'c' });
