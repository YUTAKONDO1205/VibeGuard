#!/usr/bin/env node
// vg++ — the C++ driver. Wraps clang++-18.
import { cli } from './main.mjs';

await cli({ driverName: 'vg++', mode: 'cxx' });
