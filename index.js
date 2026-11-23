/**
 * @local/dsh-redactor — Host half.
 *
 * Inserts a sanitizing adapter between `LlmRuntime` and every registered
 * provider adapter: requests leaving for the model carry surrogate values,
 * responses coming back are restored to real values. The session log, tool
 * execution and the filesystem never see a surrogate.
 */
import {
  createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, randomUUID,
} from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, copyFileSync, appendFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

const VAULT_VERSION = 2
const PEPPER = 'dsh-redactor/v1'
const DEFAULT_TAIL = 8

const DEFAULTS = {
  enabled: true,
  providers: ['*'],
  strategy: 'surrogate',
  ipPool: 'documentation',
  emailDomain: 'mask',
  autoDiscover: true,
  autoAddObserved: false,
  vaultFile: '',
  maxEntries: 5000,
}

/* ------------------------------------------------------------------ */
/* crypto                                                              */
/* ------------------------------------------------------------------ */

function detectProfileDir() {
  const direct = process.env.DSH_PROFILE_DIR
  if (typeof direct === 'string' && direct.length > 0) return direct
  const home = process.env.DSH_HOME || join(homedir(), '.dsh')
  const named = process.env.DSH_PROFILE
  if (typeof named === 'string' && named.length > 0) {
    const candidate = join(home, 'profiles', named)
    if (existsSync(candidate)) return candidate
  }
  for (const argument of process.argv) {
    if (typeof argument !== 'string') continue
    const normalized = argument.replace(/\\/g, '/')
    if (/\/profiles\/[^/]+$/.test(normalized) && existsSync(argument)) return argument
  }
  const fallback = join(home, 'profiles', 'desktop')
  if (existsSync(fallback)) return fallback
  return undefined
}

function legacyVaultFile() {
  const home = process.env.DSH_HOME || join(homedir(), '.dsh')
  return join(home, 'redactor', 'vault.bin')
}

function vaultFilePath(config) {
  if (typeof config.vaultFile === 'string' && config.vaultFile.length > 0) return config.vaultFile
  const profile = detectProfileDir()
  if (profile) return join(profile, 'plugins', 'dsh-redactor', 'vault.bin')
  return legacyVaultFile()
}

function deriveKey(salt) {
  const ikm = Buffer.from([
    PEPPER,
    process.env.DSH_PROFILE ?? '',
    process.env.DSH_PROFILE_DIR ?? '',
  ].join('\u0000'), 'utf8')
  return Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('dsh-redactor-vault', 'utf8'), 32))
}

function seal(payload, key) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  const plain = Buffer.from(JSON.stringify(payload), 'utf8')
  const body = Buffer.concat([cipher.update(plain), cipher.final()])
  return {
    nonce: nonce.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: body.toString('base64'),
  }
}

function unseal(doc, key) {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(doc.nonce, 'base64'))
  decipher.setAuthTag(Buffer.from(doc.tag, 'base64'))
  const plain = Buffer.concat([
    decipher.update(Buffer.from(doc.ct, 'base64')),
    decipher.final(),
  ])
  return JSON.parse(plain.toString('utf8'))
}

/* ------------------------------------------------------------------ */
/* deterministic pseudo random                                         */
/* ------------------------------------------------------------------ */

function makeRng(key, seed) {
  let counter = 0
  let block = Buffer.alloc(0)
  let offset = 0
  return function next(count) {
    while (block.length - offset < count) {
      const header = Buffer.alloc(4)
      header.writeUInt32BE(counter++, 0)
      const chunk = createHmac('sha256', key).update(seed).update(header).digest()
      block = offset >= block.length ? chunk : Buffer.concat([block.subarray(offset), chunk])
      offset = 0
    }
    const value = block.subarray(offset, offset + count)
    offset += count
    return value
  }
}

function pick(rng, list) {
  return list[rng(4).readUInt32BE(0) % list.length]
}

const FIRST_NAMES = ['nora', 'chen', 'liam', 'ava', 'noah', 'mia', 'ethan', 'zoe', 'lucas', 'iris', 'owen', 'ruby', 'leo', 'ella', 'kai', 'ivy']
const LAST_NAMES = ['chen', 'wang', 'liu', 'zhao', 'sun', 'zhou', 'wu', 'zheng', 'feng', 'han', 'lin', 'he', 'guo', 'gao', 'luo']
const SURNAMES = ['陈', '王', '李', '赵', '孙', '周', '吴', '郑', '冯', '韩', '林', '何', '郭', '高', '罗']
const GIVEN_NAMES = ['明', '伟', '芳', '娜', '强', '磊', '洋', '静', '敏', '杰', '涛', '艳', '勇', '娟', '军', '霞', '鹏', '婷', '斌', '雪']

function base62(rng, length) {
  const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let out = ''
  for (let i = 0; i < length; i++) out += alphabet[rng(1)[0] % alphabet.length]
  return out
}

function fakeFor(kind, real, key, opts) {
  const seed = Buffer.concat([Buffer.from(kind + '\u0000', 'utf8'), Buffer.from(real, 'utf8')])
  const rng = makeRng(key, seed)
  switch (kind) {
    case 'ipv4': {
      const nets = opts.ipPool === 'public'
        ? ['198.18.0', '203.0.113', '192.0.2']
        : ['192.0.2', '198.51.100', '203.0.113']
      const net = nets[rng(1)[0] % nets.length]
      let last = 1 + (rng(1)[0] % 254)
      let candidate = `${net}.${last}`
      while (candidate === '127.0.0.1' || candidate === '0.0.0.0') {
        last = (last % 254) + 1
        candidate = `${net}.${last}`
      }
      return candidate
    }
    case 'email': {
      const at = real.lastIndexOf('@')
      const domain = at === -1 ? '' : real.slice(at + 1)
      const local = `${pick(rng, FIRST_NAMES)}.${pick(rng, LAST_NAMES)}`
      let host = 'example.com'
      if (opts.emailDomain === 'keep' && domain) host = domain
      return `${local}@${host}`
    }
    case 'phone': {
      const head = String(3 + (rng(1)[0] % 7))
      let digits = ''
      for (let i = 0; i < 9; i++) digits += String(rng(1)[0] % 10)
      return `1${head}${digits}`
    }
    case 'idcard': {
      const area = '110101'
      const year = 1970 + (rng(1)[0] % 45)
      const month = 1 + (rng(1)[0] % 12)
      const day = 1 + (rng(1)[0] % 28)
      const seq = String(rng(1)[0] % 1000).padStart(3, '0')
      const body = `${area}${year}${String(month).padStart(2, '0')}${String(day).padStart(2, '0')}${seq}`
      return body + idCheckDigit(body)
    }
    case 'bankcard': {
      let body = '622202'
      for (let i = 0; i < 9; i++) body += String(rng(1)[0] % 10)
      return body + luhnCheckDigit(body)
    }
    case 'name':
      return `${pick(rng, SURNAMES)}${pick(rng, GIVEN_NAMES)}`
    case 'username': {
      const separator = /[._-]/.test(real) ? real.match(/[._-]/)[0] : ''
      const upper = /[A-Z]/.test(real)
      const first = pick(rng, FIRST_NAMES)
      const last = pick(rng, LAST_NAMES)
      const joined = `${first}${separator}${last}`
      return upper ? joined[0].toUpperCase() + joined.slice(1) : joined
    }
    case 'password': {
      const length = Math.max(8, Math.min(64, real.length))
      const hasUpper = /[A-Z]/.test(real)
      const hasLower = /[a-z]/.test(real)
      const hasDigit = /\d/.test(real)
      const hasSymbol = /[^A-Za-z0-9]/.test(real)
      let pool = ''
      if (hasLower) pool += 'abcdefghijkmnopqrstuvwxyz'
      if (hasUpper) pool += 'ABCDEFGHJKLMNPQRSTUVWXYZ'
      if (hasDigit) pool += '23456789'
      if (hasSymbol) pool += '!@#$%^&*-_=+'
      if (!pool) pool = 'abcdefghijkmnopqrstuvwxyz23456789'
      let out = ''
      for (let i = 0; i < length; i++) out += pool[rng(1)[0] % pool.length]
      return out
    }
    case 'token': {
      const prefix = (real.match(/^(sk-|ghp_|AKIA|glpat-)/) ?? [''])[0]
      const length = Math.max(16, Math.min(80, real.length - prefix.length))
      return prefix + base62(rng, length)
    }
    case 'host': {
      const parts = real.split('.')
      const tld = parts.length > 1 ? parts[parts.length - 1] : ''
      const head = parts[0].replace(/\d+/g, () => String(1 + (rng(1)[0] % 9)))
      const middle = parts.length > 2 ? 'corp-mail' : 'example'
      return tld ? `${head}.${middle}.${tld}` : `${head}.example`
    }
    case 'custom':
    default: {
      const length = Math.max(4, Math.min(64, real.length))
      return base62(rng, length)
    }
  }
}

function luhnCheckDigit(body) {
  let sum = 0
  for (let i = 0; i < body.length; i++) {
    let digit = Number(body[body.length - 1 - i])
    if (i % 2 === 0) {
      digit *= 2
      if (digit > 9) digit -= 9
    }
    sum += digit
  }
  return String((10 - (sum % 10)) % 10)
}

function idCheckDigit(body17) {
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
  const codes = '10X98765432'
  let sum = 0
  for (let i = 0; i < 17; i++) sum += Number(body17[i]) * weights[i]
  return codes[sum % 11]
}

/* ------------------------------------------------------------------ */
/* detection                                                           */
/* ------------------------------------------------------------------ */

const GENERIC_USERS = new Set([
  'root', 'admin', 'administrator', 'www-data', 'nobody', 'postgres', 'mysql', 'ubuntu',
  'ec2-user', 'azureuser', 'docker', 'git', 'guest', 'test', 'user', 'deployer',
])

const RESERVED_DOMAINS = /(^|\.)(example\.(com|org|net)|localhost|invalid|test)$/i
const LOCAL_HOSTS = new Set([
  'localhost', '127.0.0.1', '0.0.0.0', '::1', '127.0.0.1', '0.0.0.0',
])

function isReservedDomain(value) {
  if (LOCAL_HOSTS.has(String(value).toLowerCase())) return true
  return RESERVED_DOMAINS.test(value)
}

function isIpv4(value) {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => {
    const n = Number(part)
    return Number.isInteger(n) && n >= 0 && n <= 255
  })
}

function luhnOk(value) {
  let sum = 0
  for (let i = 0; i < value.length; i++) {
    let digit = Number(value[value.length - 1 - i])
    if (i % 2 === 1) {
      digit *= 2
      if (digit > 9) digit -= 9
    }
    sum += digit
  }
  return sum % 10 === 0
}

function idOk(value) {
  if (value.length !== 18) return false
  const body = value.slice(0, 17)
  if (!/^\d{17}$/.test(body)) return false
  return idCheckDigit(body) === value[17].toUpperCase()
}

const STRONG_RULES = [
  { kind: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { kind: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { kind: 'token', re: /(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})/g },
  { kind: 'idcard', re: /(?<!\d)\d{17}[\dXx](?!\d)/g, check: idOk },
  { kind: 'ipv4', re: /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g, check: isIpv4 },
  { kind: 'phone', re: /(?<!\d)1[3-9]\d{9}(?!\d)/g },
  { kind: 'bankcard', re: /(?<!\d)\d{16,19}(?!\d)/g, check: luhnOk },
]

const SECRET_NAME = /^(?:[a-z0-9]+[_-])*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)$/i
const ACCOUNT_NAME = /^(?:[a-z0-9]+[_-])*(?:user(?:name)?|login|account|uid)$/i

function looksLikeSecret(value) {
  if (typeof value !== 'string') return false
  if (value.length < 6 || value.length > 256) return false
  if (/[\s`'"(){}[\]|*?\\<>]/.test(value)) return false
  if (/^(?:https?:\/\/|\/|[A-Za-z]:[\\/]|\$|\{\{|__)/.test(value)) return false
  if (/^\d+$/.test(value) && value.length < 8) return false
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length
  return classes >= 2
}

function looksLikeAccount(value) {
  if (typeof value !== 'string') return false
  if (value.length < 3 || value.length > 64) return false
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) return false
  if (/^\d+$/.test(value)) return false
  if (GENERIC_USERS.has(value.toLowerCase())) return false
  return true
}

function codeRanges(text) {
  const ranges = []
  for (const match of text.matchAll(/`[^`\n]*`/g)) {
    if (typeof match.index === 'number') ranges.push([match.index, match.index + match[0].length])
  }
  return ranges
}

function inRanges(ranges, index) {
  for (const [start, end] of ranges) {
    if (index >= start && index < end) return true
  }
  return false
}

function classifyKey(key) {
  const normalized = String(key).trim()
  if (SECRET_NAME.test(normalized)) return 'password'
  if (ACCOUNT_NAME.test(normalized)) return 'username'
  return undefined
}

function skipValue(kind, value) {
  if (!value || value.length < 3) return true
  if (value.includes('${') || value.includes('{{') || value.startsWith('$')) return true
  if (kind === 'username' && GENERIC_USERS.has(value.toLowerCase())) return true
  if (kind === 'email' && isReservedDomain(value.slice(value.lastIndexOf('@') + 1))) return true
  if ((kind === 'ipv4' || kind === 'host') && isReservedDomain(value)) return true
  return false
}

function collectMatches(vault, text) {
  const found = []
  const code = codeRanges(text)
  const add = (start, end, kind, value) => {
    if (end <= start) return
    if (skipValue(kind, value)) return
    if (vault.isFake(value)) return
    if ((kind === 'password' || kind === 'username') && inRanges(code, start)) return
    found.push({ start, end, kind, value })
  }

  for (const entry of vault.manualEntries()) {
    if (entry.status !== 'active') continue
    if (entry.match === 'exact') {
      let index = 0
      while (true) {
        index = text.indexOf(entry.real, index)
        if (index === -1) break
        add(index, index + entry.real.length, entry.kind, entry.real)
        index += entry.real.length
      }
    } else {
      let re
      try {
        re = entry.match === 'glob' ? globToRegExp(entry.real) : new RegExp(entry.real, 'g')
      } catch {
        continue
      }
      for (const match of text.matchAll(re)) {
        if (typeof match.index !== 'number') continue
        add(match.index, match.index + match[0].length, entry.kind, match[0])
      }
    }
  }

  for (const rule of STRONG_RULES) {
    for (const match of text.matchAll(rule.re)) {
      if (typeof match.index !== 'number') continue
      if (rule.check && !rule.check(match[0])) continue
      add(match.index, match.index + match[0].length, rule.kind, match[0])
    }
  }

  // env / ini / yaml / export: a whole line of KEY=value.
  const envLine = /^[ \t]*(?:export[ \t]+)?(?<key>[A-Za-z_][A-Za-z0-9_.-]{1,40})[ \t]*[:=][ \t]*(?<q>["']?)(?<value>[^\s"'`,;]{3,})\k<q>[ \t]*(?:[#].*)?$/gm
  for (const match of text.matchAll(envLine)) {
    if (typeof match.index !== 'number' || !match.groups) continue
    const kind = classifyKey(match.groups.key)
    if (!kind) continue
    const value = match.groups.value
    const ok = kind === 'password' ? looksLikeSecret(value) : looksLikeAccount(value)
    if (!ok) continue
    const offset = match[0].lastIndexOf(value)
    if (offset === -1) continue
    add(match.index + offset, match.index + offset + value.length, kind, value)
  }

  // JSON: "key": "value".
  const jsonPair = /"(?<key>[A-Za-z_][A-Za-z0-9_.-]{1,40})"[ \t]*:[ \t]*"(?<value>[^"\\]{3,})"/g
  for (const match of text.matchAll(jsonPair)) {
    if (typeof match.index !== 'number' || !match.groups) continue
    const kind = classifyKey(match.groups.key)
    if (!kind) continue
    const value = match.groups.value
    const ok = kind === 'password' ? looksLikeSecret(value) : looksLikeAccount(value)
    if (!ok) continue
    const offset = match[0].lastIndexOf(value)
    if (offset === -1) continue
    add(match.index + offset, match.index + offset + value.length, kind, value)
  }

  // CLI: --flag value / --flag=value.
  const cliFlag = /(?:^|\s)--?(?<key>password|passwd|pwd|secret|token|api-key|apikey|access-key|private-key|user|username|login)(?:[ \t]+|[ \t]*=[ \t]*)(?<q>["']?)(?<value>[^\s"'`,;]{3,})\k<q>/gi
  for (const match of text.matchAll(cliFlag)) {
    if (typeof match.index !== 'number' || !match.groups) continue
    const kind = classifyKey(match.groups.key)
    if (!kind) continue
    const value = match.groups.value
    const ok = kind === 'password' ? looksLikeSecret(value) : looksLikeAccount(value)
    if (!ok) continue
    const offset = match[0].lastIndexOf(value)
    if (offset === -1) continue
    add(match.index + offset, match.index + offset + value.length, kind, value)
  }

  // Connection string: scheme://user:pass@host.
  const dsn = /\b([a-z][a-z0-9+.-]*):\/\/([^:@/\s]{2,64})(?::([^@/\s]{3,128}))?@/gi
  for (const match of text.matchAll(dsn)) {
    if (typeof match.index !== 'number') continue
    const user = match[2]
    const pass = match[3]
    const userOffset = match.index + match[0].indexOf(user)
    if (looksLikeAccount(user)) add(userOffset, userOffset + user.length, 'username', user)
    if (pass && looksLikeSecret(pass)) {
      const passOffset = match.index + match[0].indexOf(pass, userOffset + user.length)
      if (passOffset > 0) add(passOffset, passOffset + pass.length, 'password', pass)
    }
  }

  return found
}

function globToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')
  return new RegExp(`(?<![\\w.-])${escaped}(?![\\w.-])`, 'g')
}

/* ------------------------------------------------------------------ */
/* vault                                                               */
/* ------------------------------------------------------------------ */

function createVault(config, logger) {
  const opts = { ...DEFAULTS, ...config }
  const file = vaultFilePath(opts)
  let salt = randomBytes(16)
  let entries = []
  let byReal = new Map()
  let byFake = new Map()
  let maxFakeLen = 0
  let saveTimer = null

  function reindex() {
    byReal = new Map()
    byFake = new Map()
    maxFakeLen = 0
    for (const entry of entries) {
      byReal.set(entry.real, entry)
      if (entry.fake) {
        byFake.set(entry.fake, entry)
        if (entry.fake.length > maxFakeLen) maxFakeLen = entry.fake.length
      }
    }
  }

  function load() {
    try {
      if (!existsSync(file)) return
      const doc = JSON.parse(readFileSync(file, 'utf8'))
      if (doc.v !== VAULT_VERSION || typeof doc.salt !== 'string') return
      salt = Buffer.from(doc.salt, 'base64')
      const body = unseal(doc, deriveKey(salt))
      entries = Array.isArray(body.entries) ? body.entries : []
      reindex()
    } catch (error) {
      logger?.warn?.('redactor: vault could not be read; rotating to an empty vault')
      try {
        renameSync(file, `${file}.unreadable`)
      } catch { /* ignore */ }
      salt = randomBytes(16)
      entries = []
      reindex()
    }
  }

  function save() {
    try {
      mkdirSync(dirname(file), { recursive: true })
      const payload = { entries, settings: { updatedAt: Date.now() } }
      const sealed = seal(payload, deriveKey(salt))
      const doc = { v: VAULT_VERSION, kdf: 'hkdf-sha256', salt: salt.toString('base64'), ...sealed }
      const temporary = `${file}.tmp`
      writeFileSync(temporary, JSON.stringify(doc), { mode: 0o600 })
      try {
        renameSync(file, `${file}.bak`)
      } catch { /* first write */ }
      renameSync(temporary, file)
    } catch (error) {
      logger?.warn?.('redactor: vault could not be written')
      logger?.warn?.(error)
    }
  }

  function scheduleSave() {
    if (saveTimer !== null) return
    saveTimer = setTimeout(() => {
      saveTimer = null
      save()
    }, 750)
    saveTimer.unref?.()
  }

  function nextFake(kind, real) {
    let candidate = fakeFor(kind, real, deriveKey(salt), opts)
    let attempt = 0
    while ((byFake.has(candidate) || byReal.has(candidate) || candidate === real) && attempt < 8) {
      attempt++
      candidate = fakeFor(kind, `${real}\u0000${attempt}`, deriveKey(salt), opts)
    }
    return candidate
  }

  function ensureEntry(kind, real, source) {
    const existing = byReal.get(real)
    if (existing) return existing
    if (entries.length >= opts.maxEntries) return undefined
    const entry = {
      id: randomUUID(),
      kind,
      match: 'exact',
      real,
      fake: nextFake(kind, real),
      source,
      status: 'active',
      createdAt: Date.now(),
      hits: 0,
    }
    entries.push(entry)
    byReal.set(real, entry)
    byFake.set(entry.fake, entry)
    if (entry.fake.length > maxFakeLen) maxFakeLen = entry.fake.length
    scheduleSave()
    return entry
  }

  function addManual(record) {
    const real = String(record.real ?? '').trim()
    if (!real) return { ok: false, error: 'real value is required' }
    if (byReal.has(real)) return { ok: false, error: 'this value is already in the list' }
    const kind = typeof record.kind === 'string' && record.kind ? record.kind : 'custom'
    const match = ['exact', 'glob', 'regex'].includes(record.match) ? record.match : 'exact'
    const fake = typeof record.fake === 'string' && record.fake.trim()
      ? record.fake.trim()
      : nextFake(kind, real)
    if (byFake.has(fake)) return { ok: false, error: 'the surrogate is already in use' }
    const entry = {
      id: randomUUID(),
      kind,
      match,
      real,
      fake,
      source: 'manual',
      status: record.status === 'muted' ? 'muted' : 'active',
      createdAt: Date.now(),
      hits: 0,
      note: typeof record.note === 'string' ? record.note.slice(0, 200) : undefined,
    }
    entries.push(entry)
    byReal.set(real, entry)
    byFake.set(fake, entry)
    if (fake.length > maxFakeLen) maxFakeLen = fake.length
    save()
    return { ok: true, entry }
  }

  function updateEntry(id, patch) {
    const entry = entries.find((item) => item.id === id)
    if (!entry) return { ok: false, error: 'entry not found' }
    if (typeof patch?.fake === 'string' && patch.fake.trim()) {
      const fake = patch.fake.trim()
      if (fake !== entry.fake && byFake.has(fake)) return { ok: false, error: 'the surrogate is already in use' }
      byFake.delete(entry.fake)
      entry.fake = fake
      byFake.set(fake, entry)
      if (fake.length > maxFakeLen) maxFakeLen = fake.length
    }
    if (typeof patch?.status === 'string' && ['active', 'muted'].includes(patch.status)) entry.status = patch.status
    if (typeof patch?.kind === 'string' && patch.kind) entry.kind = patch.kind
    if (typeof patch?.note === 'string') entry.note = patch.note.slice(0, 200)
    save()
    return { ok: true, entry }
  }

  function removeEntry(id) {
    const index = entries.findIndex((item) => item.id === id)
    if (index === -1) return { ok: false, error: 'entry not found' }
    const [entry] = entries.splice(index, 1)
    byReal.delete(entry.real)
    if (entry.fake) byFake.delete(entry.fake)
    save()
    return { ok: true }
  }

  function manualEntries() {
    return entries.filter((entry) => entry.source === 'manual')
  }

  function isFake(value) {
    return byFake.has(value)
  }

  function restoreList() {
    return [...byFake.values()]
      .filter((entry) => entry.status === 'active' && entry.fake && entry.real)
      .sort((left, right) => right.fake.length - left.fake.length)
  }

  const legacy = legacyVaultFile()
  if (file !== legacy && !existsSync(file) && existsSync(legacy)) {
    try {
      mkdirSync(dirname(file), { recursive: true })
      copyFileSync(legacy, file)
      logger?.info?.(`redactor: migrated vault to ${file}`)
    } catch { /* keep the legacy location */ }
  }

  function clear() {
    entries = []
    reindex()
    save()
  }

  load()

  return {
    opts,
    file,
    load,
    save,
    clear,
    scheduleSave,
    ensureEntry,
    addManual,
    updateEntry,
    removeEntry,
    manualEntries,
    isFake,
    lookup: (real) => byReal.get(real),
    restoreList,
    get maxFakeLen() { return maxFakeLen },
    entries: () => entries,
    stats: () => ({
      total: entries.length,
      manual: entries.filter((entry) => entry.source === 'manual').length,
      rule: entries.filter((entry) => entry.source === 'rule').length,
      observed: entries.filter((entry) => entry.source === 'observed').length,
    }),
  }
}

/* ------------------------------------------------------------------ */
/* rewrite / restore                                                   */
/* ------------------------------------------------------------------ */

function rewriteText(vault, text, meta) {
  if (typeof text !== 'string' || text.length === 0) return text
  const matches = collectMatches(vault, text)
  if (matches.length === 0) return text
  matches.sort((left, right) => left.start - right.start || right.end - left.end)
  const chosen = []
  let cursor = 0
  for (const match of matches) {
    if (match.start < cursor) continue
    chosen.push(match)
    cursor = match.end
  }
  let output = ''
  let last = 0
  const discover = meta?.discover !== false
  for (const match of chosen) {
    output += text.slice(last, match.start)
    const entry = discover
      ? vault.ensureEntry(match.kind, match.value, 'rule')
      : vault.lookup(match.value)
    if (entry && entry.status === 'active') {
      output += entry.fake
      if (meta?.onHit) meta.onHit(entry, meta.sessionId, meta.via)
    } else {
      output += text.slice(match.start, match.end)
    }
    last = match.end
  }
  output += text.slice(last)
  return output
}

function restoreText(vault, text) {
  if (typeof text !== 'string' || text.length === 0) return text
  let output = text
  for (const entry of vault.restoreList()) {
    if (output.includes(entry.fake)) output = output.split(entry.fake).join(entry.real)
  }
  return output
}

function sanitizeBlock(vault, block, meta) {
  if (!block || typeof block !== 'object') return block
  switch (block.type) {
    case 'text':
    case 'reasoning':
      return typeof block.text === 'string' ? { ...block, text: rewriteText(vault, block.text, meta) } : block
    case 'tool-call':
      return typeof block.arguments === 'string' ? { ...block, arguments: rewriteText(vault, block.arguments, meta) } : block
    default:
      return block
  }
}

function sanitizeMessage(vault, message, meta) {
  if (!message || typeof message !== 'object') return message
  if (!Array.isArray(message.content)) return message
  const scoped = message.role === 'assistant' ? { ...meta, discover: false } : meta
  return { ...message, content: message.content.map((block) => sanitizeBlock(vault, block, scoped)) }
}

function sanitizeOptions(vault, options, hooks) {
  if (!options || typeof options !== 'object') return options
  const meta = {
    sessionId: typeof options.sessionId === 'string' ? options.sessionId : '',
    via: 'request',
    onHit: hooks?.onHit,
  }
  const output = { ...options }
  if (typeof options.system === 'string') output.system = rewriteText(vault, options.system, meta)
  if (Array.isArray(options.messages)) output.messages = options.messages.map((message) => sanitizeMessage(vault, message, meta))
  if (Array.isArray(options.tools)) {
    output.tools = options.tools.map((tool) => (
      tool && typeof tool.description === 'string'
        ? { ...tool, description: rewriteText(vault, tool.description, meta) }
        : tool
    ))
  }
  return output
}

function restoreBlock(vault, block) {
  if (!block || typeof block !== 'object') return block
  switch (block.type) {
    case 'text':
    case 'reasoning':
      return typeof block.text === 'string' ? { ...block, text: restoreText(vault, block.text) } : block
    case 'tool-call':
      return typeof block.arguments === 'string' ? { ...block, arguments: restoreText(vault, block.arguments) } : block
    default:
      return block
  }
}

async function* wrapStream(vault, source) {
  const pending = new Map()
  const tailLength = Math.max(DEFAULT_TAIL, Math.min(vault.maxFakeLen - 1, 128))
  try {
  for await (const chunk of source) {
    if (!chunk || typeof chunk !== 'object') {
      yield chunk
      continue
    }
    switch (chunk.type) {
      case 'block-start': {
        pending.set(chunk.index, { text: '', type: chunk.blockType })
        yield chunk
        break
      }
      case 'text-delta':
      case 'reasoning-delta': {
        const state = pending.get(chunk.index) ?? { text: '', type: chunk.type === 'text-delta' ? 'text' : 'reasoning' }
        state.type = chunk.type === 'text-delta' ? 'text' : 'reasoning'
        const buffer = state.text + chunk.text
        if (buffer.length <= tailLength) {
          state.text = buffer
          pending.set(chunk.index, state)
          break
        }
        const cut = buffer.length - tailLength
        state.text = buffer.slice(cut)
        pending.set(chunk.index, state)
        yield { ...chunk, text: restoreText(vault, buffer.slice(0, cut)) }
        break
      }
      case 'tool-call-delta': {
        const state = pending.get(chunk.index) ?? { text: '', type: 'tool-call', id: chunk.id }
        state.type = 'tool-call'
        state.id = chunk.id
        const buffer = state.text + chunk.argumentsDelta
        if (buffer.length <= tailLength) {
          state.text = buffer
          pending.set(chunk.index, state)
          break
        }
        const cut = buffer.length - tailLength
        state.text = buffer.slice(cut)
        pending.set(chunk.index, state)
        yield { ...chunk, argumentsDelta: restoreText(vault, buffer.slice(0, cut)) }
        break
      }
      case 'block-end': {
        const state = pending.get(chunk.index)
        pending.delete(chunk.index)
        if (state && state.text) {
          const text = restoreText(vault, state.text)
          if (state.type === 'tool-call') {
            yield { type: 'tool-call-delta', index: chunk.index, id: state.id, argumentsDelta: text }
          } else {
            yield { type: state.type === 'reasoning' ? 'reasoning-delta' : 'text-delta', index: chunk.index, text }
          }
        }
        yield { ...chunk, block: restoreBlock(vault, chunk.block) }
        break
      }
      default:
        yield chunk
    }
  }
  } finally {
    for (const [index, state] of pending) {
      if (!state || !state.text) continue
      const text = restoreText(vault, state.text)
      if (state.type === 'tool-call') {
        yield { type: 'tool-call-delta', index, id: state.id, argumentsDelta: text }
      } else {
        yield { type: state.type === 'reasoning' ? 'reasoning-delta' : 'text-delta', index, text }
      }
    }
    pending.clear()
  }
}

/* ------------------------------------------------------------------ */
/* adapter wrapper                                                     */
/* ------------------------------------------------------------------ */

class SanitizingAdapter {
  constructor(inner, vault, hooks) {
    this.__redactorWrapper = true
    this.inner = inner
    this.vault = vault
    this.hooks = hooks
  }

  providerInfo(provider) { return this.inner.providerInfo(provider) }
  providerRetryPolicy(provider) { return this.inner.providerRetryPolicy?.(provider) }
  imageRequestPricing(provider, model) { return this.inner.imageRequestPricing?.(provider, model) }
  imageRequestTarget(provider, model, image) { return this.inner.imageRequestTarget?.(provider, model, image) }
  listModels(provider) { return this.inner.listModels(provider) }
  resolveModel(provider, model, signal) { return this.inner.resolveModel(provider, model, signal) }

  async prepareCall(provider, model, signal) {
    const call = await this.inner.prepareCall(provider, model, signal)
    const self = this
    return {
      model: call.model,
      stream(options) {
        return wrapStream(self.vault, call.stream(sanitizeOptions(self.vault, options, self.hooks)))
      },
    }
  }

  stream(options) {
    return wrapStream(this.vault, this.inner.stream(sanitizeOptions(this.vault, options, this.hooks)))
  }
}

/* ------------------------------------------------------------------ */
/* HTTP bridge                                                         */
/* ------------------------------------------------------------------ */

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  })
}

function createBridge(vault, config) {
  const sessions = new Map()
  const listeners = new Set()
  const encoder = new TextEncoder()

  function broadcast() {
    const payload = `event: stats\ndata: ${JSON.stringify({ sessions: [...sessions.keys()].length })}\n\n`
    for (const controller of listeners) {
      try {
        controller.enqueue(encoder.encode(payload))
      } catch {
        listeners.delete(controller)
      }
    }
  }

  function recordHit(sessionId, entry, via) {
    if (typeof sessionId !== 'string' || !sessionId) return
    let bucket = sessions.get(sessionId)
    if (!bucket) {
      bucket = { total: 0, entries: new Map() }
      sessions.set(sessionId, bucket)
    }
    bucket.total += 1
    const current = bucket.entries.get(entry.id) ?? { hits: 0, firstAt: Date.now(), lastAt: 0, via }
    current.hits += 1
    current.lastAt = Date.now()
    current.via = via
    bucket.entries.set(entry.id, current)
    broadcast()
  }

  function sessionStats(sessionId) {
    const bucket = sessions.get(sessionId)
    if (!bucket) return { total: 0, entries: [] }
    return {
      total: bucket.total,
      entries: [...bucket.entries.entries()].map(([id, value]) => ({ id, ...value })),
    }
  }

  function listEntries(sessionId) {
    const bucket = sessions.get(sessionId)
    return vault.entries().map((entry) => ({
      id: entry.id,
      kind: entry.kind,
      match: entry.match,
      real: entry.real,
      fake: entry.fake,
      source: entry.source,
      status: entry.status,
      hits: entry.hits ?? 0,
      note: entry.note,
      sessionHits: bucket?.entries.get(entry.id)?.hits ?? 0,
      sessionVia: bucket?.entries.get(entry.id)?.via,
    }))
  }

  async function readJson(request) {
    const text = await request.text()
    if (!text) return {}
    return JSON.parse(text)
  }

  async function handle(request) {
    const url = new URL(request.url)
    const sessionId = url.searchParams.get('session') ?? ''
    const path = url.pathname

    if (request.method === 'GET' && path.endsWith('/stats')) {
      return jsonResponse({
        ok: true,
        vault: { file: vault.file, ...vault.stats() },
        session: sessionStats(sessionId),
        sessions: [...sessions.keys()].length,
      })
    }

    if (request.method === 'GET' && path.endsWith('/entries')) {
      return jsonResponse({ ok: true, entries: listEntries(sessionId) })
    }

    if (request.method === 'GET' && path.endsWith('/stream')) {
      const stream = new ReadableStream({
        start(controller) {
          listeners.add(controller)
          controller.enqueue(encoder.encode(': connected\n\n'))
          const timer = setInterval(() => {
            try {
              controller.enqueue(encoder.encode(': ping\n\n'))
            } catch {
              clearInterval(timer)
              listeners.delete(controller)
            }
          }, 15000)
          timer.unref?.()
          request.signal?.addEventListener('abort', () => {
            clearInterval(timer)
            listeners.delete(controller)
            try { controller.close() } catch { /* already closed */ }
          }, { once: true })
        },
      })
      return new Response(stream, {
        headers: {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store',
          connection: 'keep-alive',
        },
      })
    }

    if (request.method === 'POST' && path.endsWith('/entries/add')) {
      try {
        return jsonResponse({ ok: true, result: vault.addManual(await readJson(request)) })
      } catch (error) {
        return jsonResponse({ ok: false, error: String(error?.message ?? error) }, 400)
      }
    }

    if (request.method === 'POST' && path.endsWith('/entries/update')) {
      try {
        const body = await readJson(request)
        return jsonResponse({ ok: true, result: vault.updateEntry(body.id, body) })
      } catch (error) {
        return jsonResponse({ ok: false, error: String(error?.message ?? error) }, 400)
      }
    }

    if (request.method === 'POST' && path.endsWith('/entries/remove')) {
      try {
        const body = await readJson(request)
        return jsonResponse({ ok: true, result: vault.removeEntry(body.id) })
      } catch (error) {
        return jsonResponse({ ok: false, error: String(error?.message ?? error) }, 400)
      }
    }

    if (request.method === 'POST' && path.endsWith('/entries/clear')) {
      try {
        vault.clear()
        sessions.clear()
        broadcast()
        return jsonResponse({ ok: true })
      } catch (error) {
        return jsonResponse({ ok: false, error: String(error?.message ?? error) }, 400)
      }
    }

    return jsonResponse({ ok: false, error: 'not found' }, 404)
  }

  return { recordHit, handle, sessionStats }
}

function registerRoutes(ctx, vault, config) {
  const bridge = createBridge(vault, config)
  const diagFile = join(dirname(vault.file), 'diag.log')
  const diag = (message) => {
    try {
      mkdirSync(dirname(diagFile), { recursive: true })
      appendFileSync(diagFile, `${new Date().toISOString()} ${message}\n`)
    } catch { /* ignore */ }
  }

  const connection = ctx.get('connection')
  const webServer = ctx.get('webServer')
  diag(`connection=${typeof connection} fetch=${typeof connection?.fetch} register=${typeof connection?.fetch?.register} webServer=${typeof webServer?.register}`)

  const paths = [
    ['/api/redactor/stats', 'GET'],
    ['/api/redactor/entries', 'GET'],
    ['/api/redactor/stream', 'GET'],
    ['/api/redactor/entries/add', 'POST'],
    ['/api/redactor/entries/update', 'POST'],
    ['/api/redactor/entries/remove', 'POST'],
    ['/api/redactor/entries/clear', 'POST'],
  ]

  let registered = 0
  const disposers = []
  if (connection?.fetch?.register) {
    for (const [path, method] of paths) {
      try {
        disposers.push(connection.fetch.register({
          path,
          methods: [method],
          requestBody: 'buffered',
          fetch: (request) => bridge.handle(request),
        }))
        registered += 1
        diag(`ok ${method} ${path}`)
      } catch (error) {
        diag(`fail ${method} ${path}: ${error?.message ?? error}`)
      }
    }
  }

  if (registered === 0 && webServer?.register) {
    try {
      disposers.push(webServer.register({
        kind: 'prefix',
        path: '/plugin/redactor',
        resource: (request) => bridge.handle(request),
      }))
      diag('ok webServer prefix /plugin/redactor')
    } catch (error) {
      diag(`fail webServer: ${error?.message ?? error}`)
    }
  }

  return { bridge, disposers }
}

/* ------------------------------------------------------------------ */
/* plugin                                                              */
/* ------------------------------------------------------------------ */

export function apply(ctx, config = {}) {
  const merged = { ...DEFAULTS, ...config }
  if (merged.enabled === false) return
  const logger = ctx.logger
  const vault = createVault(merged, logger)
  let bridge = {
    recordHit: () => {},
    handle: async () => new Response('{"ok":false}', { status: 503 }),
    sessionStats: () => ({ total: 0, entries: [] }),
  }
  let disposers = []
  let registerTimer = null

  const tryRegister = (attempt) => {
    const connection = ctx.get('connection')
    const webServer = ctx.get('webServer')
    const ready = Boolean(connection?.fetch?.register || webServer?.register)
    if (!ready) {
      if (attempt < 150) registerTimer = setTimeout(() => tryRegister(attempt + 1), 200)
      return
    }
    const result = registerRoutes(ctx, vault, merged)
    if (result.disposers.length === 0) {
      if (attempt < 150) registerTimer = setTimeout(() => tryRegister(attempt + 1), 200)
      return
    }
    bridge = result.bridge
    disposers = result.disposers
    logger?.info?.(`redactor: HTTP bridge ready after ${attempt} attempt(s)`)
  }
  tryRegister(0)

  const hooks = {
    onHit: (entry, sessionId, via) => {
      entry.hits = (entry.hits ?? 0) + 1
      entry.lastHitAt = Date.now()
      vault.scheduleSave()
      bridge.recordHit(sessionId, entry, via)
    },
  }

  const installed = new Map()

  function install() {
    const runtime = ctx.get('llm')
    const registry = runtime && runtime.adapters
    if (!(registry instanceof Map)) {
      logger?.warn?.('redactor: llm adapter registry is not introspectable; redaction is inactive')
      return
    }
    for (const [provider, registration] of registry) {
      if (!(merged.providers.includes('*') || merged.providers.includes(provider))) continue
      const current = installed.get(provider)
      if (current && current.wrapper === registration.adapter) continue
      const original = registration.adapter
      if (!original) continue
      let inner = original
      while (inner && typeof inner === 'object' && inner.inner && inner.vault) {
        if (inner.__redactorWrapper !== true) {
          try {
            if (typeof inner.vault.load === 'function') inner.vault.load()
            else if (typeof inner.vault.clear === 'function') inner.vault.clear()
          } catch { /* ignore */ }
        }
        inner = inner.inner
      }
      if (!inner || typeof inner.stream !== 'function') continue
      const wrapper = new SanitizingAdapter(inner, vault, hooks)
      const base = original instanceof SanitizingAdapter
        ? { ...registration, adapter: inner }
        : registration
      try {
        registry.set(provider, { ...registration, adapter: wrapper })
        installed.set(provider, { registration: base, wrapper })
      } catch (error) {
        logger?.warn?.(`redactor: could not wrap provider "${provider}"`)
        logger?.warn?.(error)
      }
    }
    for (const [provider, record] of installed) {
      const registration = registry.get(provider)
      if (!registration || registration.adapter !== record.wrapper) installed.delete(provider)
    }
  }

  function restore() {
    const runtime = ctx.get('llm')
    const registry = runtime && runtime.adapters
    if (!(registry instanceof Map)) return
    for (const [provider, record] of installed) {
      const registration = registry.get(provider)
      if (registration && registration.adapter === record.wrapper) registry.set(provider, record.registration)
    }
    installed.clear()
  }

  ctx.on('llm/adapters-updated', () => {
    try { install() } catch (error) { logger?.warn?.(error) }
  })

  const timer = setTimeout(() => {
    try { install() } catch (error) { logger?.warn?.(error) }
  }, 100)
  timer.unref?.()

  ctx.effect(function* () {
    yield () => {
      clearTimeout(timer)
      if (registerTimer !== null) clearTimeout(registerTimer)
      restore()
      for (const dispose of disposers) {
        try { dispose() } catch { /* ignore */ }
      }
      try { vault.save() } catch { /* ignore */ }
    }
  })

  logger?.info?.(`redactor: vault ${vault.file} with ${vault.stats().total} entries`)
}
