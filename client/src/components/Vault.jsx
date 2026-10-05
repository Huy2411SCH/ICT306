import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { copySecret, generatePassword, safeHref, CLIPBOARD_CLEAR_SECONDS } from '../security.js';
import StrengthMeter from './StrengthMeter.jsx';

const EMPTY = { title: '', username: '', password: '', url: '', notes: '' };

function EntryForm({ initial, onSave, onCancel }) {
  const [form, setForm] = useState(initial);
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const set = (field) => (e) => setForm({ ...form, [field]: e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await onSave(form);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <form className="card form" onSubmit={submit}>
      <h3>{initial.id ? 'Edit entry' : 'New entry'}</h3>
      <label>Title<input value={form.title} onChange={set('title')} required maxLength={100} /></label>
      <label>Username / email<input value={form.username} onChange={set('username')} maxLength={200} autoComplete="off" /></label>
      <label>Password
        <div className="row">
          <input type={show ? 'text' : 'password'} value={form.password} onChange={set('password')} required maxLength={256} autoComplete="new-password" />
          <button type="button" className="ghost" onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'}</button>
          <button type="button" className="ghost" onClick={() => { setForm({ ...form, password: generatePassword(20) }); setShow(true); }}>Generate</button>
        </div>
      </label>
      <StrengthMeter password={form.password} allowAi />
      <label>Website<input value={form.url} onChange={set('url')} placeholder="https://" maxLength={500} /></label>
      <label>Notes<textarea value={form.notes} onChange={set('notes')} maxLength={2000} rows={3} /></label>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button className="primary">Save</button>
        <button type="button" className="ghost" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

export default function Vault() {
  const [entries, setEntries] = useState([]);
  const [query, setQuery] = useState('');
  const [editing, setEditing] = useState(null);
  const [revealed, setRevealed] = useState({});
  const [toast, setToast] = useState('');

  const load = () => api('/vault').then((d) => setEntries(d.entries)).catch(() => {});
  useEffect(() => { load(); }, []);

  // Revealed passwords disappear from the screen automatically after 15s.
  useEffect(() => {
    if (Object.keys(revealed).length === 0) return undefined;
    const t = setTimeout(() => setRevealed({}), 15_000);
    return () => clearTimeout(t);
  }, [revealed]);

  const reveal = async (id) => (await api(`/vault/${id}/reveal`, { method: 'POST' })).password;

  const copy = async (entry) => {
    try {
      await copySecret(await reveal(entry.id), () => setToast('Clipboard cleared'));
      setToast(`Password copied, clipboard clears in ${CLIPBOARD_CLEAR_SECONDS}s`);
    } catch (err) {
      setToast(err.message);
    }
  };

  const toggleReveal = async (id) => {
    if (revealed[id]) return setRevealed({});
    setRevealed({ [id]: await reveal(id) });
  };

  const edit = async (entry) => setEditing({ ...entry, password: await reveal(entry.id) });

  const save = async (form) => {
    const body = { title: form.title, username: form.username, password: form.password, url: form.url, notes: form.notes };
    if (form.id) await api(`/vault/${form.id}`, { method: 'PUT', body });
    else await api('/vault', { method: 'POST', body });
    setEditing(null);
    load();
  };

  const remove = async (entry) => {
    if (!window.confirm(`Delete "${entry.title}"? This cannot be undone.`)) return;
    await api(`/vault/${entry.id}`, { method: 'DELETE' });
    load();
  };

  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(''), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  if (editing) return <EntryForm initial={editing} onSave={save} onCancel={() => setEditing(null)} />;

  const q = query.toLowerCase();
  const shown = entries.filter((e) => [e.title, e.username, e.url].some((v) => v?.toLowerCase().includes(q)));

  return (
    <section>
      <div className="row between">
        <input className="search" placeholder="Search vault…" value={query} onChange={(e) => setQuery(e.target.value)} />
        <button className="primary" onClick={() => setEditing(EMPTY)}>+ Add entry</button>
      </div>
      {shown.length === 0 && <p className="muted center-text">{entries.length ? 'No matches.' : 'Your vault is empty. Add your first password.'}</p>}
      <div className="list">
        {shown.map((e) => (
          <div key={e.id} className="card entry">
            <div>
              <div className="title">{e.title}</div>
              <div className="muted small">{e.username}</div>
              {safeHref(e.url) && <a className="small" href={safeHref(e.url)} target="_blank" rel="noopener noreferrer">{e.url}</a>}
              <div className="mono">{revealed[e.id] ?? '••••••••••••'}</div>
            </div>
            <div className="actions">
              <button className="ghost" onClick={() => copy(e)}>Copy</button>
              <button className="ghost" onClick={() => toggleReveal(e.id)}>{revealed[e.id] ? 'Hide' : 'Show'}</button>
              <button className="ghost" onClick={() => edit(e)}>Edit</button>
              <button className="ghost danger" onClick={() => remove(e)}>Delete</button>
            </div>
          </div>
        ))}
      </div>
      {toast && <div className="toast">{toast}</div>}
    </section>
  );
}
