#!/usr/bin/env node
// The executable entry point: wire the server to this process's stdio.
//
// Kept separate from `server.ts` so that importing the server does not start
// one. A module with a side effect at import time cannot be unit-tested — the
// test file would attach to the real `process.stdin` the moment it loaded — and
// this is the one file in the package that is not covered by tests, precisely
// because it is the one file whose whole content is the side effect.
//
// There is no argument parsing, no `--help`, and no config file. An MCP server
// is launched by a client from a command line the client owns; every flag added
// here is a flag that has to be documented in a client configuration a user
// writes by hand. The scope of this PoC is one interception path, and a path
// with no options has none to get wrong.

import process from 'node:process';
import { serve } from './server.js';

// stderr, never stdout. On stdio transport stdout is the wire, and one stray
// byte on it desynchronises the client's parser for the rest of the session
// (see `serve`). A startup line on stderr is what makes "the server launched"
// distinguishable from "the client's spawn failed" in a client's log pane,
// which is otherwise a genuinely hard thing to tell apart.
process.stderr.write('vibeguard mcp-guard: listening on stdio (local scan, zero transmission)\n');

serve(process.stdin, process.stdout);
