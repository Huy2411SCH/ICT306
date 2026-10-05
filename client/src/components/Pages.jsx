import { useEffect, useState } from 'react';
import { api } from '../api.js';
import StrengthMeter from './StrengthMeter.jsx';

const fmt = (ts) => new Date(ts).toLocaleString();

export function PasswordCheck() {
  const [password, setPassword] = useState('');
  return (
    <section className="card narrow">
      <h3>Password check</h3>
      <p className="muted">
        Checks strength, searches known breaches (Have I Been Pwned, k-anonymity: only 5 characters of the
        password's SHA-1 hash leave the server) and gives AI advice based on the password's characteristics only.
      </p>
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Type a password to test" autoComplete="off" />
      <StrengthMeter password={password} allowAi />
    </section>
  );
}

export function Health() {
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const load = (breach) => {
    setBusy(true);
    api(`/vault/health${breach ? '?breach=1' : ''}`).then(setReport).catch(() => {}).finally(() => setBusy(false));
  };
  useEffect(() => load(false), []);
  if (!report) return <p className="muted">Loading…</p>;

  const List = ({ title, items, hint }) => (
    <div className="card">
      <h4>{title} <span className="count">{items?.length ?? '–'}</span></h4>
      <p className="muted small">{hint}</p>
      {items?.length ? <ul>{items.map((t, i) => <li key={i}>{Array.isArray(t) ? t.join(', ') : t}</li>)}</ul> : null}
    </div>
  );

  return (
    <section>
      <div className="card row between">
        <div>
          <h3>Vault health score: <span className={report.score >= 80 ? 'ok' : report.score >= 50 ? 'warn' : 'error'}>{report.score}/100</span></h3>
          <p className="muted">{report.total} entries analysed</p>
        </div>
        <button className="ghost" onClick={() => load(true)} disabled={busy}>{busy ? 'Checking…' : 'Check all for breaches'}</button>
      </div>
      <div className="grid">
        <List title="Reused passwords" items={report.reused} hint="Groups of entries sharing the same password." />
        <List title="Weak passwords" items={report.weak} hint="Strength score below 3/4." />
        <List title="Old passwords" items={report.old} hint="Not changed in 90+ days." />
        <List title="Breached passwords" items={report.breached} hint={report.breached ? 'Found in known data breaches.' : 'Click "Check all for breaches".'} />
      </div>
    </section>
  );
}

export function Activity() {
  const [events, setEvents] = useState([]);
  useEffect(() => { api('/tools/activity').then((d) => setEvents(d.events)).catch(() => {}); }, []);
  return (
    <section className="card">
      <h3>My recent activity</h3>
      <p className="muted small">If you see something you don't recognise, change your master password immediately.</p>
      <table>
        <thead><tr><th>Time</th><th>Event</th><th>IP</th><th>Device</th></tr></thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i} className={e.event.includes('failed') || e.event.includes('locked') ? 'bad' : ''}>
              <td>{fmt(e.ts)}</td><td>{e.event}</td><td>{e.ip}</td><td className="ua">{e.user_agent}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export function Settings({ me }) {
  const [currentPassword, setCurrent] = useState('');
  const [newPassword, setNew] = useState('');
  const [msg, setMsg] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api('/auth/change-password', { method: 'POST', body: { currentPassword, newPassword } });
      setCurrent('');
      setNew('');
      setMsg({ ok: true, text: 'Master password changed. Your vault key was re-wrapped.' });
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    }
  };

  return (
    <section className="card narrow">
      <h3>Settings</h3>
      <p className="muted small">
        Two-factor authentication: <strong className="ok">enabled</strong> · Auto-lock after {me.lockMinutes} min idle ·
        Clipboard auto-clear after 15 s
      </p>
      <h4>Change master password</h4>
      <form onSubmit={submit}>
        <label>Current master password<input type="password" value={currentPassword} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required /></label>
        <label>New master password<input type="password" value={newPassword} onChange={(e) => setNew(e.target.value)} autoComplete="new-password" required minLength={12} maxLength={128} /></label>
        <StrengthMeter password={newPassword} username={me.username} />
        {msg && <p className={msg.ok ? 'ok' : 'error'}>{msg.text}</p>}
        <button className="primary">Change password</button>
      </form>
    </section>
  );
}
