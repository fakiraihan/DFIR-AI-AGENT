# User Auth and Per-User Investigation History SQLite Brief

## Goal
Build real user registration and login backed by SQLite so each analyst has isolated investigation history. The upload page must only appear after the user clicks Start Investigation and authenticates.

## Product Behavior
- The landing page remains the first screen.
- Clicking Start Investigation opens an authentication gate instead of the upload page.
- The auth gate supports two modes: Login and Register.
- A successful login or registration routes the user to the upload page.
- Upload, investigation status, report retrieval, session rename, session delete, and export access are scoped to the authenticated user.
- The sidebar bottom area includes a profile surface near the existing footer/settings zone. It shows the current user's name/email, provides logout, and may expose lightweight account actions.
- Session history displays only the current user's investigations.
- Guest/no-login investigation history is no longer the target behavior for this flow.  

## Non-Goals
- No enterprise SSO, OAuth, MFA, password reset email, or admin user management in this slice.
- No multi-tenant organization/role model.
- No migration of old diskcache sessions unless a later migration task explicitly asks for it.
- No public sharing of reports between users.

## Architecture
- SQLite is the initial database.
- The database file should live under the existing runtime data boundary, for example `data/dfir_app.sqlite3`.
- Backend owns authentication, user identity, and session/report persistence.
- Frontend owns auth UI state and authenticated navigation only; it must not be the source of truth for identity.
- Prefer an HTTP-only cookie session for browser auth. If implementation constraints force a token header, the plan must document why and how it is protected.
- Passwords must be stored as strong password hashes, never plaintext.

## Data Model
Minimum tables:

- `users`
  - `id`
  - `email`
  - `name`
  - `password_hash`
  - `created_at`
  - `updated_at`

- `auth_sessions`
  - `id`
  - `user_id`
  - `session_token_hash`
  - `created_at`
  - `expires_at`
  - `revoked_at`

- `investigation_sessions`
  - `id`
  - `user_id`
  - `file_name`
  - `file_path`
  - `file_size`
  - `title`
  - `status`
  - `stage`
  - `progress`
  - `current_message`
  - `upload_time`
  - `last_update`
  - `completion_time`
  - `report_id`
  - `severity`

- `investigation_reports`
  - `id`
  - `session_id`
  - `user_id`
  - `report_json`
  - `report_path`
  - `created_at`

Optional later table:
- `activity_events` if the current in-session event list becomes too large for a JSON column or compact session metadata.

## API Contract
New auth endpoints:
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

Updated protected endpoints:
- `POST /api/upload`
- `POST /api/investigate/{session_id}`
- `GET /api/sessions`
- `PATCH /api/sessions/{session_id}`
- `DELETE /api/sessions/{session_id}`
- `GET /api/status/{session_id}`
- `GET /api/report/{session_id}`
- `GET /api/export/{session_id}`
- `POST /api/report-export/pdf` if it depends on a report/session identity

All protected endpoints must reject unauthenticated access with `401`. Endpoints with a session id must reject cross-user access with `404` or `403`; prefer `404` to avoid leaking that another user's session exists.

## Frontend UX
- `Start Investigation` sets the app into an auth gate state.
- Auth gate layout:
  - Login tab/form by default.
  - Register tab/form available in the same surface.
  - Successful auth continues directly to upload page.
- Header should not be the primary register surface.
- Sidebar bottom profile surface:
  - Shows avatar/icon, name/email, and authenticated status.
  - Provides Logout.
  - Provides a small Settings/Profile action if needed.
  - Replaces the temporary local-profile affordance from the previous prototype slice.
- History list should be empty when the authenticated user has no sessions.
- On logout, clear current session and return to landing/auth flow rather than showing another user's stale history.

## Compatibility Boundary
- Existing report JSON shape should remain compatible for frontend dashboard/export consumers.
- Existing investigation pipeline can keep its internal session id string, but it must be tied to `user_id`.
- Existing diskcache-backed `SessionStore` should be retired or wrapped only as a temporary runtime compatibility bridge. The implementation plan must name the retirement trigger.
- Existing tests for report generation should remain valid.

## Security Requirements
- Passwords are hashed with a vetted library such as `passlib[bcrypt]` or equivalent.
- Auth session tokens are random, stored hashed in SQLite, and sent via HTTP-only cookie.
- CORS/cookie settings must work for local Vite dev and FastAPI.
- User input validation:
  - email normalized lowercase
  - unique email
  - password minimum length
  - display name max length
- Session ownership is checked server-side for every user-owned resource.

## Acceptance Criteria
- Registering creates a SQLite user and logs the user in.
- Login works with the registered email/password.
- After Start Investigation, unauthenticated users see Login/Register, not Upload.
- Authenticated users see Upload.
- Upload creates an investigation history row tied to the current user.
- User A cannot see, open, rename, delete, export, or fetch report/status for User B sessions.
- Sidebar bottom shows current profile and logout.
- Logout hides upload/history and clears the active investigation view.
- Automated tests cover register/login, `GET /api/auth/me`, per-user session listing, and cross-user access rejection.

## Plan-Time Complexity Check
- Backend router ownership should split into a new `routers/auth.py` rather than adding auth logic to `main.py` or `routers/investigation.py`.
- Database ownership should be a new persistence module, not embedded in routers.
- `session_store.py` currently owns diskcache session persistence and should not become the long-term SQLite auth/session owner.
- `frontend/src/components/InvestigationPage.jsx` is already large; auth gate/profile work should use new components instead of growing it.
- `frontend/src/components/Sidebar.jsx` can host the profile surface, but profile actions should be factored if the block becomes large.

## ADR Signal
This introduces a durable persistence and authentication boundary. After implementation, consider an ADR recording:
- SQLite as prototype persistence store.
- HTTP-only cookie sessions as auth mechanism.
- Per-user ownership as the invariant for investigation history.
- Retirement path for diskcache session history.
