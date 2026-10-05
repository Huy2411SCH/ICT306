import { useEffect, useState } from 'react';
import { api } from '../api.js';

const LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];

/** Live strength + breach check. With `allowAi`, offers AI-generated advice (features only are sent to the AI). */
export default function StrengthMeter({ password, username, allowAi = false }) {
  const [result, setResult] = useState(null);
  const [checkError, setCheckError] = useState('');
  const [ai, setAi] = useState(null);
  const [aiBusy, setAiBusy] = useState(false);

  useEffect(() => {
    setAi(null);
    setCheckError('');
    if (!password) {
      setResult(null);
      return undefined;
    }
    // A response for an older password can arrive after a newer one (the breach lookup varies in
    // speed); `current` makes sure only the response for what is in the box right now is shown.
    let current = true;
    const timer = setTimeout(() => {
      api('/tools/analyze', { method: 'POST', body: { password, username } })
        .then((data) => current && setResult(data))
        .catch((err) => {
          if (!current) return;
          setResult(null);
          setCheckError(err.message);
        });
    }, 500); // debounce: don't send every keystroke
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [password, username]);

  const askAi = async () => {
    setAiBusy(true);
    try {
      setAi(await api('/tools/ai-feedback', { method: 'POST', body: { password } }));
    } catch (err) {
      setAi({ source: 'error', tips: [err.message] });
    } finally {
      setAiBusy(false);
    }
  };

  if (checkError) return <p className="warn small">Password check unavailable: {checkError}</p>;
  if (!result) return null;
  return (
    <div className="strength">
      <div className="meter"><div className={`fill s${result.score}`} data-score={result.score} /></div>
      <div className="row between">
        <strong>{LABELS[result.score]}</strong>
        <span className="muted">Crack time (offline attack): {result.crackTime}</span>
      </div>
      {result.breachCount > 0 ? (
        <p className="error">⚠ Found in {result.breachCount.toLocaleString()} breach records{result.breachSource === 'local' ? ' (offline list)' : ' (Have I Been Pwned)'}. Do not use it.</p>
      ) : (
        <p className="ok small">✓ Not found in known breaches{result.breachSource === 'local' ? ' (offline list only)' : ''}</p>
      )}
      {result.warning && <p className="warn small">{result.warning}</p>}
      {result.suggestions.length > 0 && (
        <ul className="small">{result.suggestions.map((s) => <li key={s}>{s}</li>)}</ul>
      )}
      {allowAi && (
        <div className="ai">
          <button type="button" className="ghost" onClick={askAi} disabled={aiBusy}>
            {aiBusy ? 'Analysing…' : '✨ Get AI advice'}
          </button>
          {ai && (
            <div className="ai-box">
              <div className="muted small">
                {ai.source === 'ai' ? 'AI feedback (Gemini)' : ai.source === 'rules' ? 'Rule-based feedback (AI disabled)' : 'Error'}
              </div>
              <ul>{ai.tips.map((t) => <li key={t}>{t}</li>)}</ul>
              {ai.sharedWithAi && (
                <details className="small">
                  <summary>What was sent to the AI? (never the password)</summary>
                  <pre>{JSON.stringify(ai.sharedWithAi, null, 2)}</pre>
                </details>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
