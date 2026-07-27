// vibeguard:disable-file
// Bundled known-good package data for VG-AISC-001 (Hallucinated Dependency).
//
// ZERO NETWORK AT RUNTIME: these are committed `const` arrays. VibeGuard's whole
// premise is zero-send; the rule matches a project's imports against THIS local
// set, never a registry API.
//
// CURATED SEED, regenerate offline. This is a hand-curated seed of the most
// popular npm / PyPI packages plus language builtins — enough to (a) exempt
// everyday imports from flagging and (b) give the near-miss detector real targets
// so a typo of a popular package (`expresss`, `reqeusts`) is caught. It is NOT
// exhaustive by design: `scripts/gen-aisc-known-packages.mjs` documents how to
// regenerate a larger set from a downloaded popularity dump. Coverage gaps here
// cause FALSE NEGATIVES (an unknown-but-not-near-miss name is silent — see the
// rule), never false positives, which is the safe direction for a young rule.

/** Most-popular npm package names (first path segment, scope stripped). */
export const KNOWN_NPM: readonly string[] = [
  'react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander', 'debug', 'moment',
  'request', 'async', 'bluebird', 'underscore', 'vue', 'angular', 'jquery', 'webpack', 'typescript',
  'eslint', 'prettier', 'jest', 'mocha', 'chai', 'vitest', 'rollup', 'vite', 'next', 'nuxt', 'svelte',
  'redux', 'react-redux', 'react-router', 'react-router-dom', 'styled-components', 'tailwindcss',
  'postcss', 'autoprefixer', 'sass', 'node-sass', 'less', 'ejs', 'pug', 'handlebars', 'mustache',
  'cors', 'body-parser', 'cookie-parser', 'helmet', 'morgan', 'passport', 'jsonwebtoken', 'bcrypt',
  'bcryptjs', 'argon2', 'dotenv', 'config', 'winston', 'pino', 'bunyan', 'uuid', 'nanoid',
  'classnames', 'prop-types', 'immer', 'rxjs', 'core-js', 'regenerator-runtime', 'tslib', 'semver',
  'glob', 'minimatch', 'rimraf', 'mkdirp', 'fs-extra', 'chokidar', 'cross-env', 'concurrently',
  'nodemon', 'ts-node', 'tsx', 'esbuild', 'terser', 'uglify-js', 'browserify', 'gulp', 'grunt',
  'karma', 'cypress', 'playwright', 'puppeteer', 'supertest', 'nock', 'sinon', 'enzyme', 'node-fetch',
  'got', 'superagent', 'ws', 'socket.io', 'socket.io-client', 'mongoose', 'mongodb', 'mysql', 'mysql2',
  'pg', 'sqlite3', 'better-sqlite3', 'sequelize', 'typeorm', 'prisma', 'redis', 'ioredis', 'knex',
  'graphql', 'apollo-server', 'express-session', 'connect-redis', 'multer', 'sharp', 'jimp', 'joi',
  'yup', 'zod', 'ajv', 'validator', 'class-validator', 'class-transformer', 'reflect-metadata',
  'inversify', 'date-fns', 'dayjs', 'luxon', 'numeral', 'big.js', 'decimal.js', 'qs', 'query-string',
  'url-parse', 'form-data', 'formidable', 'busboy', 'archiver', 'tar', 'unzipper', 'adm-zip', 'xml2js',
  'fast-xml-parser', 'csv-parse', 'csv-parser', 'papaparse', 'cheerio', 'jsdom', 'marked',
  'markdown-it', 'highlight.js', 'prismjs', 'dompurify', 'sanitize-html', 'xss', 'escape-html', 'he',
  'iconv-lite', 'mime', 'mime-types', 'content-type', 'accepts', 'negotiator', 'etag', 'fresh',
  'range-parser', 'send', 'serve-static', 'finalhandler', 'on-finished', 'destroy', 'encodeurl',
  'escape-string-regexp', 'ansi-styles', 'strip-ansi', 'supports-color', 'color-convert', 'wrap-ansi',
  'ora', 'inquirer', 'prompts', 'yargs', 'minimist', 'meow', 'boxen', 'figlet', 'cli-table3', 'listr',
  'execa', 'shelljs', 'which', 'node-notifier', 'open', 'clipboardy', 'update-notifier', 'ini', 'rc',
  'cosmiconfig', 'lilconfig', 'deepmerge', 'merge', 'object-assign', 'extend', 'clone', 'klona',
  'fast-deep-equal', 'dequal', 'shallowequal', 'react-is', 'scheduler', 'hoist-non-react-statics',
  'react-transition-group', 'framer-motion', 'react-spring', 'antd', 'bootstrap', 'react-bootstrap',
  'formik', 'react-hook-form', 'swr', 'react-query', 'recoil', 'zustand', 'jotai', 'mobx', 'mobx-react',
  'redux-thunk', 'redux-saga', 'reselect', 'history', 'axios-retry', 'p-limit', 'p-queue', 'p-retry',
  'lru-cache', 'node-cron', 'cron', 'bull', 'bullmq', 'agenda', 'nodemailer', 'stripe', 'aws-sdk',
  'firebase', 'firebase-admin', 'googleapis', 'twilio', 'sendgrid', 'dotenv-expand',
  'cross-fetch', 'undici', 'abort-controller', 'eventemitter3', 'events', 'readable-stream', 'through2',
  'split2', 'pump', 'end-of-stream', 'once', 'wrappy', 'inherits', 'util-deprecate', 'safe-buffer',
  // Real popular packages that are edit-distance-1 from another list entry and so
  // would otherwise be flagged as near-misses of it (preact↔react, enquirer↔
  // inquirer, merge2↔merge). MUST list every such real package explicitly — a
  // coverage gap here is a false positive, not just a false negative. This is the
  // residual cost of an allowlist-only design (no lockfile veto in 0.2.x); audit
  // against a popularity dump when regenerating (scripts/gen-aisc-known-packages).
  'preact', 'enquirer', 'merge2',
  // Popular packages added to reduce false negatives.
  'lodash-es', 'react-native', 'styled-jsx', 'use-debounce', 'react-icons', 'fastify', 'hono',
  'openai', 'anthropic', 'langchain', 'zod-to-json-schema', 'drizzle-orm',
  // ---------------------------------------------------------------------------
  // §17z-a CORPUS AUDIT (2026-07-28). Same category as preact/enquirer/merge2
  // above, but found by MEASUREMENT instead of by memory: every name below is a
  // real package declared in the dependency manifests of the evaluation corpora
  // (paper_data/corpus1k + corpus1k_vibe, 2765 package.json files → 3953 distinct
  // registry names) that sat edit-distance-1 from a name already on this list —
  // i.e. a GUARANTEED false positive on every project that depends on it.
  //
  // Reproduce:
  //   node scripts/aisc-corpus-extract.mjs --out-npm npm.json --out-pypi pypi.json
  //   node scripts/gen-aisc-known-packages.mjs --audit --npm-real npm.json --pypi-real pypi.json
  // The auditor iterates to a CLOSURE (an addition is itself a new near-miss
  // target, so it can create fresh false positives): npm converged after 1
  // productive round, PyPI after 1.
  //
  // The near-neighbour that made each one fire is noted, because the temptation
  // when this list is next edited will be to "clean up" what look like obscure
  // packages — deleting any of them re-opens a measured false positive.
  'aws-cdk',        // ~ aws-sdk
  'cli-table',      // ~ cli-table3
  'clipboard',      // ~ clipboardy
  'eclint',         // ~ eslint
  'eventemitter2',  // ~ eventemitter3
  'jsdoc',          // ~ jsdom
  'kcors',          // ~ cors
  'mssql',          // ~ mysql
  'ntypescript',    // ~ typescript
  'preact-router',  // ~ react-router
  'prompt',         // ~ prompts
  'through',        // ~ through2
  'tslint',         // ~ eslint
  'xml-js',         // ~ xml2js
  'xtend',          // ~ extend
];

/** Most-popular PyPI package names (first dotted segment, normalized). */
export const KNOWN_PYPI: readonly string[] = [
  'requests', 'urllib3', 'boto3', 'botocore', 'setuptools', 'six', 'python-dateutil', 'pyyaml',
  'numpy', 'pandas', 'scipy', 'matplotlib', 'pip', 'wheel', 'certifi', 'idna', 'charset-normalizer',
  'chardet', 'click', 'flask', 'django', 'jinja2', 'werkzeug', 'itsdangerous', 'markupsafe',
  'sqlalchemy', 'alembic', 'psycopg2', 'psycopg2-binary', 'pymysql', 'mysqlclient', 'redis', 'celery',
  'kombu', 'amqp', 'pytz', 'tzdata', 'cryptography', 'pyopenssl', 'cffi', 'pycparser', 'bcrypt',
  'passlib', 'pyjwt', 'oauthlib', 'requests-oauthlib', 'google-auth', 'protobuf', 'grpcio', 'aiohttp',
  'async-timeout', 'attrs', 'multidict', 'yarl', 'frozenlist', 'aiosignal', 'fastapi', 'starlette',
  'uvicorn', 'pydantic', 'pydantic-core', 'typing-extensions', 'annotated-types', 'httpx', 'httpcore',
  'h11', 'sniffio', 'anyio', 'pytest', 'pytest-cov', 'coverage', 'tox', 'mock', 'hypothesis', 'flake8',
  'pyflakes', 'pycodestyle', 'mccabe', 'black', 'isort', 'mypy', 'mypy-extensions', 'pylint', 'astroid',
  'autopep8', 'yapf', 'bandit', 'safety', 'pre-commit', 'virtualenv', 'pipenv', 'poetry', 'twine',
  'build', 'packaging', 'pyparsing', 'pluggy', 'iniconfig', 'tomli', 'tomlkit', 'colorama', 'termcolor',
  'rich', 'tqdm', 'pillow', 'opencv-python', 'scikit-learn', 'scikit-image', 'seaborn', 'plotly',
  'bokeh', 'dash', 'statsmodels', 'sympy', 'networkx', 'nltk', 'spacy', 'gensim', 'transformers',
  'torch', 'tensorflow', 'keras', 'xgboost', 'lightgbm', 'catboost', 'joblib', 'threadpoolctl',
  'cython', 'numba', 'llvmlite', 'h5py', 'openpyxl', 'xlrd', 'xlsxwriter', 'lxml', 'beautifulsoup4',
  'bs4', 'soupsieve', 'html5lib', 'feedparser', 'scrapy', 'selenium', 'playwright', 'pymongo',
  'elasticsearch', 'paramiko', 'fabric', 'ansible', 'docker', 'kubernetes', 'jsonschema', 'marshmallow',
  'gunicorn', 'gevent', 'greenlet', 'eventlet', 'tornado', 'sanic', 'bottle', 'graphene',
  'strawberry-graphql', 'rq', 'apscheduler', 'schedule', 'watchdog', 'python-dotenv', 'environs',
  'dynaconf', 'loguru', 'structlog', 'sentry-sdk', 'prometheus-client', 's3transfer', 'jmespath',
  'awscli', 'google-cloud-storage', 'azure-core', 'openai', 'anthropic', 'langchain', 'tiktoken',
  'huggingface-hub', 'datasets', 'accelerate', 'sentencepiece', 'safetensors', 'einops', 'wandb',
  // psycopg (v3, the current PostgreSQL driver) is a REAL package DL-1 from
  // psycopg2 — must be listed or it false-flags. Same category as preact/merge2.
  'psycopg',
  // Common IMPORT names that differ from the PyPI package name (import cv2 →
  // opencv-python). Listed so `import <alias>` is not mistaken for an unknown.
  'cv2', 'sklearn', 'pil', 'yaml', 'dateutil', 'jwt', 'dotenv', 'skimage', 'google', 'grpc',
  // ---------------------------------------------------------------------------
  // §17z-a CORPUS AUDIT (2026-07-28), part 1 — SEPARATOR CONFUSION, the largest
  // measured false-positive class on the Python side and the one the hand-curated
  // seed could not see.
  //
  // PyPI distribution names are hyphenated but the MODULE you import is the
  // underscore form (PEP 503 treats `-`, `_` and `.` as equivalent). Because this
  // list held only the hyphenated distribution name, the rule's normalized-key
  // branch read the *correct* import as separator confusion and flagged it:
  //   import typing_extensions  →  "did you mean typing-extensions?"  ← FP
  // Every entry below was observed as a real `import` statement in the corpora
  // (38k .py files scanned) or as a normalized requirement in a real manifest.
  //
  // REJECTED for this batch: the underscore form of distributions whose module is
  // named something else entirely (opencv-python→cv2, scikit-image→skimage,
  // python-dotenv→dotenv, python-dateutil→dateutil, strawberry-graphql→strawberry,
  // google-auth→google.auth, azure-core→azure.core). `import opencv_python` is not
  // a thing anyone writes, so listing it would only widen the near-miss target set
  // — manufacturing new false positives to fix none.
  'typing_extensions', 'charset_normalizer', 'huggingface_hub', 'sentry_sdk', 'prometheus_client',
  'async_timeout', 'mypy_extensions', 'pydantic_core', 'requests_oauthlib', 'scikit_learn',
  // Not observed in the corpus sample, but the same mechanical case: these ARE the
  // module names their (already-listed) distributions install, so the FP is latent
  // rather than absent.
  'pre_commit', 'annotated_types', 'pytest_cov',
  // §17z-a CORPUS AUDIT part 2 — real distributions edit-distance-1 from a listed
  // name, found in real requirements.txt / pyproject.toml files. Same rule as the
  // npm block: the near-neighbour is noted so nobody "tidies" one away.
  'authlib',        // ~ oauthlib
  'dateutils',      // ~ dateutil        (a distinct real distribution)
  // httpx2 is the Pydantic-stewarded successor distribution of httpx (PyPI 2.9.1,
  // 2026-07-24), declared by five corpus repositories. It looks exactly like a
  // slopsquat of `httpx` and was very nearly rejected on that basis — registry
  // existence was checked at authoring time before it went in. Same shape as the
  // psycopg2→psycopg succession already documented below.
  'httpx2',         // ~ httpx
  'pymssql',        // ~ pymysql
  'scapy',          // ~ scipy
  'simpy',          // ~ sympy
  // §17z-a CORPUS AUDIT part 3 — CLOSURE. Adding a name does not only silence it,
  // it also creates a new near-miss TARGET, so a second real name one edit away
  // becomes a false positive that did not exist before the fix. `scanpy` is that
  // case, produced by `scapy` on the line above and caught only because the audit
  // re-runs until a round is empty. Round 2 of the corpus closure; round 3 empty.
  'scanpy',         // ~ scapy (added in part 2) — real, and imported in the corpus
  // Real MODULES shipped by distributions already on this list, observed as real
  // imports in the corpora. Same category as the cv2/sklearn aliases above.
  '_pytest',        // ~ pytest — pytest internals, imported by every plugin
  'blackd',         // ~ black  — the black daemon module
  // Python 2 stdlib. PY_STDLIB is the Python 3 list, so legacy files reading
  // `import urllib2` were flagged as a near-miss of urllib3.
  'urllib2',
];

/** Node.js core modules (the `node:` prefix is stripped before lookup). */
export const NODE_BUILTINS: ReadonlySet<string> = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console', 'constants', 'crypto',
  'dgram', 'diagnostics_channel', 'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https',
  'inspector', 'module', 'net', 'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring',
  'readline', 'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls', 'trace_events', 'tty', 'url',
  'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
]);

/** Python standard-library top-level module names. */
export const PY_STDLIB: ReadonlySet<string> = new Set([
  '__future__', '__main__', 'abc', 'aifc', 'argparse', 'array', 'ast', 'asyncio', 'atexit', 'audioop',
  'base64', 'bdb', 'binascii', 'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'chunk', 'cmath', 'cmd',
  'code', 'codecs', 'codeop', 'collections', 'colorsys', 'compileall', 'concurrent', 'configparser',
  'contextlib', 'contextvars', 'copy', 'copyreg', 'cProfile', 'csv', 'ctypes', 'curses', 'dataclasses',
  'datetime', 'dbm', 'decimal', 'difflib', 'dis', 'doctest', 'email', 'encodings', 'ensurepip', 'enum',
  'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch', 'fractions', 'ftplib',
  'functools', 'gc', 'getopt', 'getpass', 'gettext', 'glob', 'graphlib', 'grp', 'gzip', 'hashlib',
  'heapq', 'hmac', 'html', 'http', 'imaplib', 'imghdr', 'importlib', 'inspect', 'io', 'ipaddress',
  'itertools', 'json', 'keyword', 'linecache', 'locale', 'logging', 'lzma', 'mailbox', 'marshal',
  'math', 'mimetypes', 'mmap', 'modulefinder', 'multiprocessing', 'netrc', 'numbers', 'operator',
  'os', 'pathlib', 'pdb', 'pickle', 'pickletools', 'pkgutil', 'platform', 'plistlib', 'poplib', 'posix',
  'pprint', 'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri',
  'random', 're', 'readline', 'reprlib', 'resource', 'runpy', 'sched', 'secrets', 'select', 'selectors',
  'shelve', 'shlex', 'shutil', 'signal', 'site', 'smtplib', 'sndhdr', 'socket', 'socketserver',
  'sqlite3', 'ssl', 'stat', 'statistics', 'string', 'stringprep', 'struct', 'subprocess', 'sunau',
  'symtable', 'sys', 'sysconfig', 'syslog', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'textwrap',
  'threading', 'time', 'timeit', 'tkinter', 'token', 'tokenize', 'tomllib', 'trace', 'traceback',
  'tracemalloc', 'tty', 'turtle', 'types', 'typing', 'unicodedata', 'unittest', 'urllib', 'uuid',
  'venv', 'warnings', 'wave', 'weakref', 'webbrowser', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc', 'zipapp',
  'zipfile', 'zipimport', 'zlib', 'zoneinfo',
]);

/**
 * Bare names that are almost always LOCAL path aliases (tsconfig `paths`, webpack
 * resolve, Python namespace packages), not registry packages. Never flagged.
 */
export const ALIAS_STOPLIST: ReadonlySet<string> = new Set([
  'utils', 'util', 'lib', 'libs', 'app', 'apps', 'config', 'configs', 'types', 'constants', 'helpers',
  'helper', 'components', 'component', 'hooks', 'store', 'stores', 'api', 'apis', 'core', 'common',
  'shared', 'server', 'client', 'src', 'test', 'tests', 'models', 'model', 'services', 'service',
  'index', 'main', 'routes', 'router', 'controllers', 'controller', 'middleware', 'middlewares', 'db',
  'database', 'schema', 'schemas', 'styles', 'style', 'assets', 'public', 'dist', 'build', 'pages',
  'page', 'views', 'view', 'layouts', 'layout', 'context', 'contexts', 'providers', 'provider',
  'reducers', 'reducer', 'actions', 'action', 'selectors', 'sagas', 'graphql', 'generated', 'proto',
  'protos', 'internal', 'domain', 'features', 'feature', 'modules', 'module', 'plugins', 'plugin',
]);

/**
 * Names documented in the slopsquatting literature as LLM-hallucinated packages
 * that squatters have (or could) register. High confidence when hit. SEED — add
 * to it from published slopsquatting corpora; keep entries that are documented,
 * not guessed.
 */
export const CURATED_HALLUCINATIONS: ReadonlySet<string> = new Set([
  // The canonical documented example: an LLM repeatedly invented `huggingface-cli`
  // as an installable package (the real tooling ships inside `huggingface-hub`),
  // and a researcher registered the name to demonstrate the attack.
  'huggingface-cli',
  // ---------------------------------------------------------------------------
  // §17z-c (2026-07-28). npm names that ALL FIVE evaluated frontier models invent
  // identically, from the published disclosure set of:
  //   A. Churilov, "The Range Shrinks, the Threat Remains: Re-evaluating LLM
  //   Package Hallucinations on the 2026 Frontier-Model Cohort", arXiv:2605.17062
  //   (rev. 2026-06-11); disclosure/npm_universal_hallucinations.csv in
  //   github.com/churik5/slopsquatting-replication-2026 (also Zenodo
  //   10.5281/zenodo.19859120), reported by Socket:
  //   socket.dev/blog/slopsquatting-targets-across-frontier-llms
  // The study disclosed these to PyPI Security and Socket; they were still
  // registrable as of 2026-04. Each name below was RE-CHECKED against
  // registry.npmjs.org on 2026-07-28 and returned 404, and none appears among the
  // 3,953 real npm dependency names extracted from paper_data/corpus1k(+_vibe).
  //
  // EXCLUDED from the same CSV, deliberately:
  //   - `metro-evaluator` and `ssh-keys`: they now return 200. Whoever holds them,
  //     the name is no longer unclaimed, and this list must never accuse a name
  //     that resolves.
  //   - `@ember/service`, `@ember/object`, `@ember/routing`, `@ember/controller`:
  //     the models hallucinate them as npm PACKAGES, but they are real Ember
  //     module paths shipped inside `ember-source` — `import Service from
  //     '@ember/service'` is correct code. (The rule skips scoped specifiers
  //     anyway, so they could never fire; the reason they are excluded is that
  //     they are not hallucinations of the kind this list means.)
  //   - THE ENTIRE PyPI HALF of the disclosure set (109 names). Its unit of
  //     analysis is the `pip install <name>` target, not the `import` statement.
  //     A model saying "pip install objc" is hallucinating a DISTRIBUTION — but
  //     `import objc` is real code (pyobjc ships that module). The same holds for
  //     git (GitPython), urllib2 (py2 stdlib), win32api/win32com (pywin32), paho
  //     (paho-mqtt), ruamel, opentelemetry, cairo, rospy, sphinxcontrib, allure,
  //     vlc, hamcrest and most of the rest. VG-AISC-001 reads IMPORTS, so copying
  //     that list in would flag real imports at HIGH confidence — the single worst
  //     failure mode this rule has. The npm half does not have the mismatch
  //     because an npm import specifier IS the package name.
  //
  // RESIDUAL RISK (accepted, not solved): a company with an internal package
  // genuinely named e.g. `network-util` gets a high-confidence false positive.
  // The near-miss branch is immune to this by construction (internal names are
  // silent unless they collide with a popular one); the curated branch is not.
  // §17z-b's `declaredPackages` veto is the intended fix — a name the project
  // actually declares should never be reported, curated or not.
  'css-color-stop',
  'dns-sd',
  'dom-ains',
  'iana-language-tag',
  'istanbul-converter',
  'istanbul-instrumenter-babel',
  'jest-xml',
  'network-util',
  'react-randomized',
  'rollup-plugin-es6',
  'terminal-align',
  'unhandled-promise-rejections',
]);
