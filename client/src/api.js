// Thin fetch wrapper. Cookies are HttpOnly, so the session is never touched from JavaScript.
export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const handlers = { onLocked: () => {}, onLoggedOut: () => {} };
export const setApiHandlers = (h) => Object.assign(handlers, h);

export async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(`/api${path}`, {
    method,
    credentials: 'same-origin',
    headers: method === 'GET' ? {} : { 'Content-Type': 'application/json' },
    body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 423) handlers.onLocked();
    else if (res.status === 401 && !path.startsWith('/auth/')) handlers.onLoggedOut();
    throw new ApiError(res.status, data.error ?? 'Request failed');
  }
  return data;
}
