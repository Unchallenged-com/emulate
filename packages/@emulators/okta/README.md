# @emulators/okta

Okta identity provider emulation with OAuth 2.0 / OIDC, user management, groups, apps, and authorization servers.

Part of [emulate](https://github.com/vercel-labs/emulate) — local drop-in replacement services for CI and no-network sandboxes.

## Install

```bash
npm install @emulators/okta
```

## Endpoints

### OAuth / OIDC

Default org server and custom authorization server paths (`/oauth2/:authServerId/...`):

- `GET /.well-known/openid-configuration` — OIDC discovery (default)
- `GET /oauth2/:authServerId/.well-known/openid-configuration` — per-server discovery
- `GET /oauth2/v1/keys` — JSON Web Key Set (JWKS)
- `GET /oauth2/v1/authorize` — authorization endpoint
- `POST /oauth2/v1/token` — token endpoint
- `GET /oauth2/v1/userinfo` — user info
- `POST /oauth2/v1/revoke` — token revocation
- `POST /oauth2/v1/introspect` — token introspection
- `GET /oauth2/v1/logout` — end session

### Users
- `GET /api/v1/users` — list users
- `POST /api/v1/users` — create user
- `GET /api/v1/users/me` — current user (from token)
- `GET /api/v1/users/:userId` — get user
- `PUT /api/v1/users/:userId` — replace user
- `POST /api/v1/users/:userId` — partial update
- `DELETE /api/v1/users/:userId` — delete user
- `GET /api/v1/users/:userId/groups` — list user groups
- `POST /api/v1/users/:userId/lifecycle/activate` — activate
- `POST /api/v1/users/:userId/lifecycle/deactivate` — deactivate
- `POST /api/v1/users/:userId/lifecycle/suspend` — suspend
- `POST /api/v1/users/:userId/lifecycle/unsuspend` — unsuspend
- `POST /api/v1/users/:userId/lifecycle/reactivate` — reactivate

### Groups
- `GET /api/v1/groups` — list groups
- `POST /api/v1/groups` — create group
- `GET /api/v1/groups/:groupId` — get group
- `PUT /api/v1/groups/:groupId` — update group
- `DELETE /api/v1/groups/:groupId` — delete group
- `GET /api/v1/groups/:groupId/users` — list group members
- `PUT /api/v1/groups/:groupId/users/:userId` — add user to group
- `DELETE /api/v1/groups/:groupId/users/:userId` — remove user from group

### Apps
- `GET /api/v1/apps` — list apps
- `POST /api/v1/apps` — create app
- `GET /api/v1/apps/:appId` — get app
- `PUT /api/v1/apps/:appId` — update app
- `DELETE /api/v1/apps/:appId` — delete app
- `GET /api/v1/apps/:appId/users` — list assigned users
- `PUT /api/v1/apps/:appId/users/:userId` — assign user
- `DELETE /api/v1/apps/:appId/users/:userId` — unassign user
- `POST /api/v1/apps/:appId/lifecycle/activate` — activate app
- `POST /api/v1/apps/:appId/lifecycle/deactivate` — deactivate app

### Authorization Servers
- `GET /api/v1/authorizationServers` — list
- `POST /api/v1/authorizationServers` — create
- `GET /api/v1/authorizationServers/:authServerId` — get
- `PUT /api/v1/authorizationServers/:authServerId` — update
- `DELETE /api/v1/authorizationServers/:authServerId` — delete
- `POST /api/v1/authorizationServers/:authServerId/lifecycle/activate` — activate
- `POST /api/v1/authorizationServers/:authServerId/lifecycle/deactivate` — deactivate

### Event hooks and log streams

Event hooks are created `ACTIVE` and `UNVERIFIED`. Verifying one sends Okta's one-time `GET` with an `x-okta-verification-challenge` header, which the endpoint must echo as `{"verification": "..."}`; an active, verified hook then receives the event-hook-eligible events it subscribes to, batched, as `POST` requests in Okta's `com.okta.event_hook` envelope with its headers and authentication header. Requests time out after 3 seconds and are retried once (deliveries only on timeouts and `5xx` answers); a failed delivery is recorded as `event_hook.delivery`. Okta requires HTTPS endpoints; the emulator also accepts `http://` on the loopback interface. Changing a hook's channel requires a new verification, and only inactive hooks can be deleted.

- `GET`, `POST /api/v1/eventHooks` — list, create event hooks
- `GET`, `PUT`, `DELETE /api/v1/eventHooks/:eventHookId` — get, replace, delete an event hook
- `POST /api/v1/eventHooks/:eventHookId/lifecycle/activate`, `deactivate` and `verify`

Log streams (`aws_eventbridge`, `splunk_cloud_logstreaming`) are stored with Okta's settings checks and recorded as `system.log_stream.lifecycle.*`; the emulator does not send events to AWS EventBridge or Splunk Cloud. The Splunk HEC token is never returned.

- `GET`, `POST /api/v1/logStreams` — list, create log streams
- `GET`, `PUT`, `DELETE /api/v1/logStreams/:logStreamId` — get, replace, delete a log stream
- `POST /api/v1/logStreams/:logStreamId/lifecycle/activate` and `deactivate`

### System Log

The emulator records what users, administrators and clients do as Okta's System Log events (LogEvent records, with Okta's event types, actor, client address, targets, outcome and transaction):

- Sign-ins: `user.session.start` at the sign-in page, `user.authentication.sso` when a user signs in to an app linked to the OIDC client (its `credentials.oauthClient.client_id`), `app.generic.unauth_app_access_attempt` when that app refuses an unassigned user, and `user.session.end` at logout with an `id_token_hint` the emulator issued.
- OAuth, as `app.oauth2.*` for the org server and `app.oauth2.as.*` for custom servers: `authorize.code`, `token.grant.access_token`, `token.grant.id_token` and `token.grant.refresh_token` for each token a grant issues, and `token.revoke` when a known token is revoked.
- Users: `user.lifecycle.create`, `activate`, `deactivate`, `suspend`, `unsuspend`, `reactivate`, `delete.initiated` and `delete.completed`, `user.account.update_profile`, and `user.session.clear` when the user's sessions are revoked.
- Groups: `group.lifecycle.create` and `delete`, `group.profile.update`, `group.user_membership.add` and `remove`.
- Apps: `application.lifecycle.create`, `update`, `activate`, `deactivate` and `delete`, `application.user_membership.add` and `remove`.
- Authorization servers: `oauth2.as.created`, `updated`, `activated`, `deactivated` and `deleted`.

A management call is recorded with the token's user as the actor and the API token's id in `transaction.detail.requestApiTokenId`; a call made with a client credentials access token has the service app as the actor. Geolocation and network fields (`geographicalContext`, `securityContext`) are null.

- `GET /api/v1/logs` lists events with `since`, `until`, `after`, `filter` (SCIM expressions with `eq`, `ne`, `co`, `sw`, `ew`, `gt`, `ge`, `lt`, `le`, `pr`, `and`, `or`, `not` and parentheses), `q` (keywords), `limit` (default 100, at most 1000) and `sortOrder`. A polling request (no `until`, ascending) always answers a `next` link, even with no new events; other requests answer one only while results remain. Events older than 90 days are not returned.

## Seed Configuration

```yaml
okta:
  users:
    - login: testuser@example.com
      email: testuser@example.com
      firstName: Test
      lastName: User
  groups:
    - name: Everyone
      description: All users
  apps:
    - name: My App
      label: My App
  authorization_servers:
    - name: default
      audiences: ["api://default"]
```

## Links

- [Full documentation](https://emulate.dev)
- [GitHub](https://github.com/vercel-labs/emulate)
