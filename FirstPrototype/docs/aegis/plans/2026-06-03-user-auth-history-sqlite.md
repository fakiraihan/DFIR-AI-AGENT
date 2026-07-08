# User Auth and Per-User Investigation History SQLite Implementation Plan

## Goal
Implement the approved SQLite-backed user registration/login flow and per-user investigation history from `docs/aegis/specs/2026-06-03-user-auth-history-sqlite-brief.md`.

## Architecture
- Backend auth owner: `backend/routers/auth.py`.
- Backend persistence owner: new `backend/modules/auth_store.py`.
- Auth mechanism: HTTP-only cookie session backed by SQLite `auth_sessions`.
- User-owned investigation metadata remains compatible with existing `SessionStore`, but every new session is tagged to `user_id` and every user-facing session endpoint enforces owner checks.
- Frontend auth gate owner: new `frontend/src/components/AuthGate.jsx`.
- Sidebar profile owner: `frontend/src/components/Sidebar.jsx`, with profile UI only; auth calls remain in `App.jsx` handlers.

## Tech Stack
- FastAPI
- SQLite via Python stdlib `sqlite3`
- Password hashing via `hashlib.pbkdf2_hmac` plus per-user salt, avoiding a new dependency install for this slice
- React 18 + Material UI

## Baseline/Authority Refs
- Spec: `docs/aegis/specs/2026-06-03-user-auth-history-sqlite-brief.md`
- Existing session APIs: `backend/routers/investigation.py`
- Existing upload flow: `backend/routers/upload.py`
- Existing app navigation: `frontend/src/App.jsx`
- Existing sidebar history: `frontend/src/components/Sidebar.jsx`

## Compatibility Boundary
- Existing report JSON shape remains unchanged.
- Existing background investigation pipeline can continue using session id strings.
- Existing report generator tests must remain green.
- Existing diskcache session storage is retained as runtime state for this slice, but user ownership and auth are enforced on API boundaries. Later ADR/plan can fully migrate session state to SQLite.

## Verification
Run:

```powershell
python -m unittest test_auth_api test_sessions_api test_export_api
python -m unittest test_report_generator
npm run build
```

Manual/browser:
- Open `http://127.0.0.1:3000`.
- Click Start Investigation.
- Confirm Login/Register gate appears before upload.
- Register a user and confirm upload page appears.
- Confirm sidebar bottom profile shows the user and logout.

## Plan Basis
- Fact: existing app has diskcache-backed session history and no real auth.
- Fact: prior prototype added local profile in header; this must be replaced by auth gate/profile surface.
- Assumption: SQLite file under `data/dfir_app.sqlite3` is acceptable for local prototype runtime.
- Unknown: whether future deployment will require Postgres; keep repository boundary small enough to swap later.

## Files
- Create `backend/modules/auth_store.py`
- Create `backend/routers/auth.py`
- Create `backend/test_auth_api.py`
- Modify `backend/main.py`
- Modify `backend/routers/upload.py`
- Modify `backend/routers/investigation.py`
- Modify `backend/config.py`
- Create `frontend/src/components/AuthGate.jsx`
- Modify `frontend/src/App.jsx`
- Modify `frontend/src/components/Header.jsx`
- Modify `frontend/src/components/Sidebar.jsx`
- Modify `frontend/src/components/UploadPage.jsx`

## Architecture Integrity Lens
- Invariant: identity and session ownership are server-side facts.
- Canonical owner: auth route + auth store own user/session auth; routers consume `get_current_user`.
- Responsibility overlap: `SessionStore` still stores runtime investigation state, but does not decide identity.
- Higher-level simplification: full SQLite session repository is deferred; current owner check is enough to protect existing APIs.
- Retirement/falsifier: if background status/report persistence needs cross-process durability beyond diskcache, migrate `SessionStore` to SQLite.
- Verdict: proceed with auth owner + API-boundary enforcement.

## Plan-Time Complexity Check
- `frontend/src/components/InvestigationPage.jsx` is over 800 lines; do not add auth UI there.
- `frontend/src/components/Sidebar.jsx` is moderately large; keep profile footer compact.
- `backend/routers/investigation.py` owns many endpoints; owner checks can be helper-level edits, not embedded auth logic.
- Recommendation: add owner files for auth store/gate, edit existing routers only at boundary checks.

## Task 1: Backend Auth Store and Auth API
Files:
- Create `backend/modules/auth_store.py`
- Create `backend/routers/auth.py`
- Create `backend/test_auth_api.py`
- Modify `backend/main.py`
- Modify `backend/config.py`

Steps:
1. Write tests for register, duplicate email rejection, login, me, logout.
2. Verify RED with `python -m unittest test_auth_api`.
3. Implement SQLite schema creation, password hashing, auth session creation, cookie set/clear.
4. Include auth router in `main.py`.
5. Verify GREEN with `python -m unittest test_auth_api`.

## Task 2: Protect Session/Upload/Report APIs By User
Files:
- Modify `backend/routers/upload.py`
- Modify `backend/routers/investigation.py`
- Extend `backend/test_auth_api.py` or `backend/test_sessions_api.py`

Steps:
1. Write tests proving unauthenticated upload/session access is rejected and User A cannot list/open User B sessions.
2. Verify RED.
3. Add `get_current_user` dependency to protected endpoints.
4. Store `user_id`/`user_profile` on upload-created sessions.
5. Filter `/api/sessions` by current user and check ownership for session-id endpoints.
6. Verify GREEN with `python -m unittest test_auth_api test_sessions_api test_export_api`.

## Task 3: Frontend Auth Gate After Start Investigation
Files:
- Create `frontend/src/components/AuthGate.jsx`
- Modify `frontend/src/App.jsx`
- Modify `frontend/src/components/Header.jsx`
- Modify `frontend/src/components/UploadPage.jsx`

Steps:
1. Add app auth state: `currentUser`, auth loading, `authGate` view state.
2. Make `Start Investigation` route unauthenticated users to `AuthGate`.
3. `AuthGate` supports Login/Register tabs and calls `/api/auth/*`.
4. Remove header-local create account as the primary register action.
5. Pass authenticated user to upload only for display; backend identity comes from cookie.
6. Verify with `npm run build`.

## Task 4: Sidebar Profile Surface
Files:
- Modify `frontend/src/components/Sidebar.jsx`
- Modify `frontend/src/App.jsx`

Steps:
1. Add bottom profile block with name/email and logout.
2. Hide user history until authenticated.
3. Refresh history after login/logout and session changes.
4. On logout, clear current session and return to landing/auth flow.
5. Verify with `npm run build` and browser check.

## Risks
- Cookie auth across Vite proxy needs `withCredentials` support; same-origin proxy should keep it simple.
- Diskcache default permissions in sandbox can affect tests; tests should override auth DB path/cache path where needed.
- Full DB migration of old sessions is intentionally deferred.

## Retirement
- Retire previous local-profile header affordance from the prior prototype slice.
- Retain `SessionStore` only as runtime investigation state for this slice.
- Future retirement trigger: migrate session/report runtime state to SQLite when old session history no longer needs diskcache compatibility.
