window.__ModuleLoader__.load({
  id: '@local/dsh-redactor',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useEffect, useRef, useCallback } = React

    const BASES = ['/api/redactor', '/plugin/redactor']

    const KIND_LABEL = {
      ipv4: 'IP', email: '邮箱', phone: '手机', idcard: '身份证', bankcard: '银行卡',
      name: '姓名', username: '账号', password: '密码', token: '密钥', host: '主机', custom: '自定义',
    }
    const SOURCE_LABEL = { manual: '手动', rule: '规则', observed: '观察', candidate: '候选' }
    const VIA_LABEL = {
      request: '请求', 'user-message': '用户消息', 'tool-result': '工具结果', 'tool-call': '工具参数', system: '系统',
    }
    const KINDS = ['ipv4', 'email', 'phone', 'idcard', 'bankcard', 'name', 'username', 'password', 'token', 'host', 'custom']

    async function call(path, options) {
      let failure
      for (const base of BASES) {
        try {
          const response = await fetch(base + path, { credentials: 'same-origin', ...options })
          if (response.status === 404) {
            failure = new Error('endpoint unavailable')
            continue
          }
          return await response.json()
        } catch (error) {
          failure = error
        }
      }
      throw failure ?? new Error('endpoint unavailable')
    }

    function useLiveSignal() {
      const [signal, setSignal] = useState(0)
      const timer = useRef(null)
      useEffect(() => {
        let source
        let sourceGeneration = 0
        let disposed = false
        const bump = () => {
          if (timer.current) return
          timer.current = setTimeout(() => {
            timer.current = null
            setSignal((value) => value + 1)
          }, 400)
        }
        const open = async () => {
          for (const base of BASES) {
            try {
              const probe = await fetch(`${base}/stats`, { credentials: 'same-origin' })
              if (!probe.ok) continue
              if (disposed) return
              sourceGeneration += 1
              source = new EventSource(`${base}/stream`)
              source.addEventListener('stats', bump)
              source.onerror = () => {}
              return
            } catch { /* try next */ }
          }
        }
        void open()
        return () => {
          disposed = true
          try { source?.close() } catch { /* ignore */ }
          if (timer.current) {
            clearTimeout(timer.current)
            timer.current = null
          }
          void sourceGeneration
        }
      }, [])
      return signal
    }

    const styles = {
      root: {
        height: '100%', overflow: 'auto', boxSizing: 'border-box',
        padding: '18px 22px 32px', color: 'var(--dsw-alias-label-primary)',
        background: 'var(--dsw-alias-bg-base)', fontSize: '13px', lineHeight: 1.5,
      },
      header: {
        display: 'flex', alignItems: 'baseline', gap: '12px', flexWrap: 'wrap', marginBottom: '14px',
      },
      title: { fontSize: '15px', fontWeight: 600, margin: 0 },
      dim: { color: 'var(--dsw-alias-label-secondary)' },
      tabs: { display: 'flex', gap: '6px', marginBottom: '14px' },
      tab: (active) => ({
        border: '1px solid var(--dsw-alias-border-l1)',
        background: active ? 'var(--dsw-alias-bg-layer-2)' : 'transparent',
        color: active ? 'var(--dsw-alias-label-primary)' : 'var(--dsw-alias-label-secondary)',
        borderRadius: '8px', padding: '5px 12px', cursor: 'pointer', fontSize: '12px',
      }),
      card: {
        border: '1px solid var(--dsw-alias-border-l1)', borderRadius: '10px',
        background: 'var(--dsw-alias-bg-layer-1)', marginBottom: '14px', overflow: 'hidden',
      },
      row: {
        display: 'grid', gridTemplateColumns: '1.6fr 1.6fr 74px 84px 64px 56px 60px',
        gap: '8px', alignItems: 'center', padding: '7px 12px',
        borderTop: '1px solid var(--dsw-alias-border-l1)',
      },
      head: {
        display: 'grid', gridTemplateColumns: '1.6fr 1.6fr 74px 84px 64px 56px 60px',
        gap: '8px', padding: '8px 12px', fontSize: '11px',
        color: 'var(--dsw-alias-label-secondary)', background: 'var(--dsw-alias-bg-layer-2)',
      },
      mono: { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: '12px', wordBreak: 'break-all' },
      badge: (tone) => ({
        display: 'inline-block', padding: '1px 7px', borderRadius: '999px', fontSize: '11px',
        border: '1px solid var(--dsw-alias-border-l1)',
        color: tone === 'warn' ? 'var(--dsw-alias-state-warn-primary)'
          : tone === 'ok' ? 'var(--dsw-alias-state-success-primary)'
            : 'var(--dsw-alias-label-secondary)',
      }),
      button: (primary) => ({
        border: '1px solid ' + (primary ? 'var(--dsw-alias-brand-primary)' : 'var(--dsw-alias-border-l1)'),
        background: primary ? 'var(--dsw-alias-brand-primary)' : 'transparent',
        color: primary ? '#fff' : 'var(--dsw-alias-label-primary)',
        borderRadius: '7px', padding: '4px 10px', cursor: 'pointer', fontSize: '12px',
      }),
      input: {
        border: '1px solid var(--dsw-alias-border-l1)', background: 'var(--dsw-alias-bg-base)',
        color: 'var(--dsw-alias-label-primary)', borderRadius: '7px', padding: '5px 8px',
        fontSize: '12px', width: '100%', boxSizing: 'border-box',
      },
      form: { display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', padding: '10px 12px' },
      error: { color: 'var(--dsw-alias-state-error-primary)', fontSize: '12px', padding: '0 12px 8px' },
    }

    function Empty(props) {
      return h('div', { style: { padding: '22px 12px', color: 'var(--dsw-alias-label-secondary)', fontSize: '12px' } }, props.text)
    }

    function EntryRow(props) {
      const { entry, onRemove, onToggle } = props
      return h('div', { style: styles.row },
        h('span', { style: styles.mono }, entry.real),
        h('span', { style: styles.mono }, entry.fake),
        h('span', {}, h('span', { style: styles.badge() }, KIND_LABEL[entry.kind] ?? entry.kind)),
        h('span', {}, h('span', { style: styles.badge(entry.source === 'manual' ? 'ok' : undefined) }, SOURCE_LABEL[entry.source] ?? entry.source)),
        h('span', { style: styles.dim }, String(entry.sessionHits ?? 0)),
        h('span', { style: styles.dim }, String(entry.hits ?? 0)),
        h('span', { style: { display: 'flex', gap: '4px' } },
          h('button', { style: styles.button(false), onClick: () => onToggle(entry) }, entry.status === 'active' ? '停用' : '启用'),
          h('button', { style: styles.button(false), onClick: () => onRemove(entry) }, '删除'),
        ),
      )
    }

    function SessionTable(props) {
      const { stats, entries } = props
      if (!stats || !stats.entries || stats.entries.length === 0) {
        return h(Empty, { text: '本会话还没有命中任何敏感信息。' })
      }
      const byId = new Map(entries.map((entry) => [entry.id, entry]))
      const rows = stats.entries
        .map((hit) => ({ hit, entry: byId.get(hit.id) }))
        .filter((item) => item.entry)
        .sort((left, right) => right.hit.hits - left.hit.hits)
      return h('div', {},
        h('div', { style: styles.head },
          h('span', {}, '真值'), h('span', {}, '假值'), h('span', {}, '类型'),
          h('span', {}, '触发点'), h('span', {}, '次数'), h('span', {}, ''), h('span', {}, ''),
        ),
        rows.map(({ hit, entry }) => h('div', { key: entry.id, style: styles.row },
          h('span', { style: styles.mono }, entry.real),
          h('span', { style: styles.mono }, entry.fake),
          h('span', {}, h('span', { style: styles.badge() }, KIND_LABEL[entry.kind] ?? entry.kind)),
          h('span', {}, h('span', { style: styles.badge() }, VIA_LABEL[hit.via] ?? hit.via ?? '请求')),
          h('span', { style: styles.dim }, String(hit.hits)),
          h('span', { style: styles.dim }, entry.source === 'manual' ? '手动' : '自动'),
          h('span', {}),
        )),
      )
    }

    function AddForm(props) {
      const { onAdded } = props
      const [real, setReal] = useState('')
      const [kind, setKind] = useState('ipv4')
      const [fake, setFake] = useState('')
      const [match, setMatch] = useState('exact')
      const [error, setError] = useState('')
      const [busy, setBusy] = useState(false)

      const submit = async () => {
        if (!real.trim() || busy) return
        setBusy(true)
        setError('')
        try {
          const result = await call('/entries/add', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ real: real.trim(), kind, fake: fake.trim(), match }),
          })
          if (!result.ok || result.result?.ok === false) {
            setError(result.error ?? result.result?.error ?? '添加失败')
          } else {
            setReal('')
            setFake('')
            onAdded()
          }
        } catch (err) {
          setError(String(err?.message ?? err))
        } finally {
          setBusy(false)
        }
      }

      return h('div', {},
        h('div', { style: styles.form },
          h('input', {
            style: { ...styles.input, flex: '2 1 220px' },
            placeholder: match === 'regex' ? '正则表达式，例如 EMP\\d{6}' : match === 'glob' ? '通配符，例如 10.2.11.*' : '真值，例如 10.2.11.2',
            value: real,
            onChange: (event) => setReal(event.target.value),
            onKeyDown: (event) => { if (event.key === 'Enter') void submit() },
          }),
          h('select', { style: { ...styles.input, width: '110px' }, value: kind, onChange: (event) => setKind(event.target.value) },
            KINDS.map((value) => h('option', { key: value, value }, KIND_LABEL[value] ?? value)),
          ),
          h('select', { style: { ...styles.input, width: '100px' }, value: match, onChange: (event) => setMatch(event.target.value) },
            h('option', { value: 'exact' }, '精确'),
            h('option', { value: 'glob' }, '通配'),
            h('option', { value: 'regex' }, '正则'),
          ),
          h('input', {
            style: { ...styles.input, flex: '1 1 160px' },
            placeholder: '假值（留空自动生成）',
            value: fake,
            onChange: (event) => setFake(event.target.value),
          }),
          h('button', { style: styles.button(true), onClick: submit, disabled: busy }, '添加'),
        ),
        error ? h('div', { style: styles.error }, error) : null,
      )
    }

    function RedactorView(props) {
      const sessionId = typeof props?.sessionId === 'string' ? props.sessionId : ''
      const signal = useLiveSignal()
      const [tab, setTab] = useState('session')
      const [stats, setStats] = useState(null)
      const [entries, setEntries] = useState([])
      const [error, setError] = useState('')

      const refresh = useCallback(async () => {
        try {
          const [nextStats, nextEntries] = await Promise.all([
            call(`/stats?session=${encodeURIComponent(sessionId)}`),
            call(`/entries?session=${encodeURIComponent(sessionId)}`),
          ])
          setStats(nextStats)
          setEntries(Array.isArray(nextEntries.entries) ? nextEntries.entries : [])
          setError('')
        } catch (err) {
          setError(String(err?.message ?? err))
        }
      }, [sessionId])

      useEffect(() => { void refresh() }, [refresh, signal])

      const remove = async (entry) => {
        try {
          await call('/entries/remove', {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: entry.id }),
          })
          void refresh()
        } catch (err) { setError(String(err?.message ?? err)) }
      }

      const toggle = async (entry) => {
        try {
          await call('/entries/update', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ id: entry.id, status: entry.status === 'active' ? 'muted' : 'active' }),
          })
          void refresh()
        } catch (err) { setError(String(err?.message ?? err)) }
      }

      const clearAll = async () => {
        try {
          await call('/entries/clear', {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
          })
          void refresh()
        } catch (err) { setError(String(err?.message ?? err)) }
      }

      const sessionTotal = stats?.session?.total ?? 0
      const distinctHits = stats?.session?.entries?.length ?? 0
      const vault = stats?.vault ?? {}

      return h('div', { style: styles.root },
        h('div', { style: styles.header },
          h('h2', { style: styles.title }, '敏感信息'),
          h('span', { style: styles.dim }, `本会话 ${distinctHits} 条不同敏感项 · 累计替换 ${sessionTotal} 次 · 词表 ${vault.total ?? 0} 条（手动 ${vault.manual ?? 0} / 规则 ${vault.rule ?? 0}）`),
        ),
        h('div', { style: styles.tabs },
          h('button', { style: styles.tab(tab === 'session'), onClick: () => setTab('session') }, '本会话'),
          h('button', { style: styles.tab(tab === 'global'), onClick: () => setTab('global') }, '全局词表'),
        ),
        error ? h('div', { style: { ...styles.error, padding: '0 0 10px' } }, error) : null,
        tab === 'session'
          ? h('div', { style: styles.card }, h(SessionTable, { stats: stats?.session, entries }))
          : h('div', {},
            h('div', { style: styles.card },
              h(AddForm, { onAdded: () => void refresh() }),
              h('div', { style: { display: 'flex', justifyContent: 'flex-end', padding: '0 12px 10px' } },
                h('button', { style: styles.button(false), onClick: clearAll }, '清空全部'),
              ),
            ),
            h('div', { style: styles.card },
              entries.length === 0
                ? h(Empty, { text: '词表为空。添加一条，或等模型请求命中内置规则。' })
                : h('div', {},
                  h('div', { style: styles.head },
                    h('span', {}, '真值'), h('span', {}, '假值'), h('span', {}, '类型'),
                    h('span', {}, '来源'), h('span', {}, '本会话'), h('span', {}, '总计'), h('span', {}, '操作'),
                  ),
                  entries.map((entry) => h(EntryRow, {
                    key: entry.id, entry, onRemove: remove, onToggle: toggle,
                  })),
                ),
            ),
            h('div', { style: { ...styles.dim, fontSize: '11px', padding: '0 2px' } },
              `词表加密存放于 ${vault.file ?? 'profile 目录'}`),
          ),
      )
    }

    let redactorCount = 0

    function CountProbe(props) {
      const sessionId = typeof props?.sessionId === 'string' ? props.sessionId : ''
      const signal = useLiveSignal()
      useEffect(() => {
        let disposed = false
        ;(async () => {
          try {
            const stats = await call(`/stats?session=${encodeURIComponent(sessionId)}`)
            if (!disposed) redactorCount = stats?.session?.entries?.length ?? 0
          } catch { /* keep previous */ }
        })()
        return () => { disposed = true }
      }, [sessionId, signal])
      return null
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('conversation.view', () => ctx.slots.register({
          name: 'conversation.view', id: 'redactor', order: 20,
          label: () => (redactorCount > 0 ? `敏感信息 ${redactorCount}` : '敏感信息'),
        }, RedactorView))
        ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register({
          name: 'conversation.session.header.actions', id: 'redactor-probe', order: 90,
        }, CountProbe))
      },
    }
  },
})
