import { useEffect, useState } from 'react';
import { api } from '../api.js';
import StrengthMeter from './StrengthMeter.jsx';

function Card({ title, subtitle, children }) {
  return (
    <div className="center">
      <div className="card auth">
        <h1>🔐 SecureVault</h1>
        <h2>{title}</h2>
        {subtitle && <p className="muted">{subtitle}</p>}
        {children}
      </div>
    </div>
  );
}

export function AuthScreen({ onDone }) {
  const [mode, setMode] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    setInfo('');
    setBusy(true);
    try {
      if (mode === 'register') {
        await api('/auth/register', { method: 'POST', body: { username, password } });
        setMode('login');
        setPassword('');
        setInfo('Account created. Log in to set up two-factor authentication.');
      } else {
        await api('/auth/login', { method: 'POST', body: { username, password } });
        setPassword('');
        onDone();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title={mode === 'login' ? 'Log in' : 'Create account'}
      subtitle={mode === 'register' ? 'Your master password encrypts your vault. It cannot be recovered, so make it long and memorable.' : null}
    >
      <form onSubmit={submit}>
        <label>Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required maxLength={32} />
        </label>
        <label>Master password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'} required maxLength={128} />
        </label>
        {mode === 'register' && <StrengthMeter password={password} username={username} />}
        {error && <p className="error">{error}</p>}
        {info && <p className="ok">{info}</p>}
        <button className="primary" disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Log in' : 'Create account'}</button>
      </form>
      <button className="link" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); setInfo(''); }}>
        {mode === 'login' ? 'No account? Register' : 'Have an account? Log in'}
      </button>
    </Card>
  );
}

export function TotpScreen({ setup, onDone, onCancel }) {
  const [qr, setQr] = useState(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (setup) api('/auth/totp/setup', { method: 'POST' }).then(setQr).catch((e) => setError(e.message));
  }, [setup]);

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await api('/auth/totp/verify', { method: 'POST', body: { code } });
      onDone();
    } catch (err) {
      setCode('');
      setError(err.message);
      if (err.status === 403 || (err.status === 401 && err.message === 'Not authenticated')) onCancel();
    }
  };

  return (
    <Card
      title={setup ? 'Set up two-factor authentication' : 'Two-factor authentication'}
      subtitle={setup
        ? 'Scan this QR code with Google Authenticator, Microsoft Authenticator or Authy, then enter the 6-digit code.'
        : 'Enter the 6-digit code from your authenticator app.'}
    >
      {setup && qr && (
        <div className="qr">
          <img src={qr.qr} alt="TOTP QR code" />
          <details><summary>Can't scan? Enter key manually</summary><code>{qr.secret}</code></details>
        </div>
      )}
      <form onSubmit={submit}>
        <input className="code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          inputMode="numeric" autoComplete="one-time-code" placeholder="123456" autoFocus />
        {error && <p className="error">{error}</p>}
        <button className="primary" disabled={code.length !== 6}>Verify</button>
      </form>
      <button className="link" onClick={onCancel}>Cancel</button>
    </Card>
  );
}

export function LockScreen({ username, onDone, onLogout }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await api('/auth/unlock', { method: 'POST', body: { password } });
      setPassword('');
      onDone();
    } catch (err) {
      setPassword('');
      setError(err.message);
      if (err.status === 403 || (err.status === 401 && err.message === 'Not authenticated')) onLogout();
    }
  };

  return (
    <Card title="Vault locked" subtitle={`The vault key was wiped from memory. Enter the master password for ${username} to unlock.`}>
      <form onSubmit={submit}>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required />
        {error && <p className="error">{error}</p>}
        <button className="primary">Unlock</button>
      </form>
      <button className="link" onClick={onLogout}>Log out</button>
    </Card>
  );
}
