// Negative: only popular / builtin / relative / scoped imports, plus one obscure
// but not-near-miss internal name (proving unknown != flagged). VG-AISC-001 must
// stay silent.
import express from 'express';
import _ from 'lodash';
import fs from 'fs';
import { helper } from './utils';
import widget from 'my-internal-corp-widget';

export { express, _, fs, helper, widget };
