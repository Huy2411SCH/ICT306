import { useEffect, useState } from 'react';
import { api } from '../api.js';

const fmt = (ts) => new Date(ts).toLocaleString();

function Alerts() {
  const [data, setData] = useState(null);
  useEffect(() => { api('/admin/alerts').then(setData).catch(() => {}); }, []);
  if (!data) return <p className="muted">Loading…</p>;
  const risky = Object.entries(data.riskByUser).sort((a, b) => b[1] - a[1]);
  return (
    <>
      <div className="grid">
        <div className="card">
          <h4>Risk score by user</h4>
          {risky.length === 0 ? <p className="muted small">No suspicious behaviour detected.</p> : (
            <table><tbody>{risky.map(([u, s]) => <tr key={u}><td>{u}</td><td><span className={s >= 6 ? 'error' : 'warn'}>{s}</span></td></tr>)}</tbody></table>
          )}
        </div>
        <div className="card">
          <h4>Detection rules</h4>
          <ul className="small">{Object.entries(data.rules).map(([k, v]) => <li key={k}><code>{k}</code>: {v}</li>)}</ul>
        </div>
      </div>
      <div className="card">
        <h4>Alerts (last 30 days) <span className="count">{data.alerts.length}</span></h4>
        <table>
          <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Details</th><th>IP</th></tr></thead>
          <tbody>
            {data.alerts.map((a, i) => (
              <tr key={i}>
                <td>{fmt(a.ts)}</td>
                <td><span className={`sev ${a.severity}`}>{a.severity}</span></td>
                <td title={a.description}>{a.rule}</td>
                <td>{a.message}</td>
                <td>{a.ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Users() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState('');
  const load = () => api('/admin/users').then((d) => setUsers(d.users)).catch(() => {});
  useEffect(() => { load(); }, []);

  const act = async (fn) => {
    setError('');
    try { await fn(); load(); } catch (err) { setError(err.message); }
  };

  return (
    <div className="card">
      <h4>Users</h4>
      <p className="muted small">Admins can manage accounts but cannot decrypt any user's vault (no such endpoint exists).</p>
      {error && <p className="error">{error}</p>}
      <table>
        <thead><tr><th>User</th><th>Role</th><th>2FA</th><th>Entries</th><th>Status</th><th>Created</th><th /></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.username}</td>
              <td><span className={`badge ${u.role}`}>{u.role}</span></td>
              <td>{u.totp_enabled ? '✓' : '—'}</td>
              <td>{u.entry_count}</td>
              <td>{u.locked ? <span className="error">locked</span> : u.failed_attempts ? `${u.failed_attempts} failed` : 'ok'}</td>
              <td>{fmt(u.created_at)}</td>
              <td className="actions">
                {u.locked && <button className="ghost" onClick={() => act(() => api(`/admin/users/${u.id}/unlock`, { method: 'POST' }))}>Unlock</button>}
                <button className="ghost" onClick={() => act(() => api(`/admin/users/${u.id}/role`, { method: 'PUT', body: { role: u.role === 'admin' ? 'user' : 'admin' } }))}>
                  Make {u.role === 'admin' ? 'user' : 'admin'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuditLog() {
  const [events, setEvents] = useState([]);
  const [chain, setChain] = useState(null);
  useEffect(() => { api('/admin/audit').then((d) => setEvents(d.events)).catch(() => {}); }, []);
  const verify = () => api('/admin/audit/verify').then(setChain).catch(() => {});

  return (
    <div className="card">
      <div className="row between">
        <h4>Security audit log</h4>
        <button className="ghost" onClick={verify}>Verify integrity</button>
      </div>
      {chain && (
        <p className={chain.valid ? 'ok' : 'error'}>
          {chain.valid ? `✓ Hash chain intact (${chain.checked} records verified)` : `✗ TAMPERING DETECTED at record #${chain.brokenAtId}`}
        </p>
      )}
      <table>
        <thead><tr><th>#</th><th>Time</th><th>User</th><th>Event</th><th>IP</th><th>Details</th></tr></thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id} className={/failed|locked|denied|blocked|csrf|rate/.test(e.event) ? 'bad' : ''}>
              <td>{e.id}</td><td>{fmt(e.ts)}</td><td>{e.username}</td><td>{e.event}</td><td>{e.ip}</td>
              <td className="mono small">{e.details}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Admin() {
  const [view, setView] = useState('alerts');
  return (
    <section>
      <div className="row">
        {['alerts', 'users', 'audit'].map((v) => (
          <button key={v} className={view === v ? 'tab active' : 'tab'} onClick={() => setView(v)}>
            {{ alerts: 'Behaviour alerts', users: 'Users', audit: 'Audit log' }[v]}
          </button>
        ))}
      </div>
      {view === 'alerts' && <Alerts />}
      {view === 'users' && <Users />}
      {view === 'audit' && <AuditLog />}
    </section>
  );
}
