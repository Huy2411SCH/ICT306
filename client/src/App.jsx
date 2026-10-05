import { useCallback, useEffect, useState } from 'react';
import { api, setApiHandlers } from './api.js';
import { clearClipboard, useIdleLock } from './security.js';
import { AuthScreen, TotpScreen, LockScreen } from './components/AuthScreens.jsx';
import Vault from './components/Vault.jsx';
import { PasswordCheck, Health, Activity, Settings } from './components/Pages.jsx';
import Admin from './components/Admin.jsx';

const TABS = [
  { id: 'vault', label: 'Vault' },
  { id: 'check', label: 'Password check' },
  { id: 'health', label: 'Vault health' },
  { id: 'activity', label: 'My activity' },
  { id: 'settings', label: 'Settings' },
  { id: 'admin', label: 'Admin', adminOnly: true },
];

export default function App() {
  const [me, setMe] = useState(undefined); // undefined = loading
  const [tab, setTab] = useState('vault');

  const refresh = useCallback(() => api('/auth/me').then(setMe).catch(() => setMe({ stage: null })), []);

  useEffect(() => {
    setApiHandlers({
      onLocked: () => setMe((m) => (m ? { ...m, stage: 'locked' } : m)),
      onLoggedOut: () => setMe({ stage: null }),
    });
    refresh();
  }, [refresh]);

  const lock = useCallback(async () => {
    await clearClipboard();
    await api('/auth/lock', { method: 'POST' }).catch(() => {});
    refresh();
  }, [refresh]);

  const logout = async () => {
    await clearClipboard();
    await api('/auth/logout', { method: 'POST' }).catch(() => {});
    setTab('vault');
    setMe({ stage: null });
  };

  useIdleLock(me?.stage === 'full', me?.lockMinutes ?? 5, lock);

  if (me === undefined) return <div className="center muted">Loading…</div>;
  if (!me.stage) return <AuthScreen onDone={refresh} />;
  if (me.stage === 'totp' || me.stage === 'totp-setup') {
    return <TotpScreen setup={me.stage === 'totp-setup'} onDone={refresh} onCancel={logout} />;
  }
  if (me.stage === 'locked') return <LockScreen username={me.username} onDone={refresh} onLogout={logout} />;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">🔐 SecureVault</div>
        <nav>
          {TABS.filter((t) => !t.adminOnly || me.role === 'admin').map((t) => (
            <button key={t.id} className={tab === t.id ? 'tab active' : 'tab'} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
        <div className="user">
          <span className="muted">
            {me.username} <span className={`badge ${me.role}`}>{me.role}</span>
          </span>
          <button className="ghost" onClick={lock}>Lock</button>
          <button className="ghost" onClick={logout}>Log out</button>
        </div>
      </header>
      <main>
        {tab === 'vault' && <Vault />}
        {tab === 'check' && <PasswordCheck />}
        {tab === 'health' && <Health />}
        {tab === 'activity' && <Activity />}
        {tab === 'settings' && <Settings me={me} />}
        {tab === 'admin' && me.role === 'admin' && <Admin />}
      </main>
    </div>
  );
}
