// VG-AISC-001 positive: near-miss / hallucinated package imports (slopsquatting).
const express = require('expresss');
const _ = require('lodahs');
const hf = require('huggingface-cli');

module.exports = { express, _, hf };
