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
]);
