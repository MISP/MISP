# MISP Web UI – Account – Auth Keys Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Auth key – read only](#account-key-read-only) | |
| 2 | [Auth key – allowed IPs](#account-key-allowed-ips) | |
| 3 | [Auth key – invalid allowed IP](#account-key-invalid-ip) | |
| 4 | [Auth key – expiration in the past](#account-key-expired) | |
| 5 | [Auth keys – only my keys](#account-key-own-only) | |

---


# E2E Tests

### Auth key – read only
<a id="account-key-read-only"></a>

A read-only key can read but not write

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/auth_keys/index`.
3. Add an auth key with the comment `QA read-only` and tick read only.
4. Use this key to list events, then to create an event (e.g. with `curl -H 'Authorization: <key>'` on `/events/index` and `/events/add`).

**Expected:** listing works; creating an event is refused with "You do not have permission to use this functionality."

**Seeded data:** Through the API, for `qa-user-a`: GET `/events/index` → HTTP 200, POST `/events/add` → HTTP 403 with that message.

### Auth key – allowed IPs
<a id="account-key-allowed-ips"></a>

A key restricted to an IP cannot be used from another IP

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/auth_keys/index`.
3. Add an auth key with the comment `QA ip allowlist` and the allowed IP `10.9.9.9`.
4. Use it from your computer to list events.

**Expected:** the request is refused with "It is not possible to use this Auth key from your IP address".

**Seeded data:** Through the API from `172.18.0.1`: HTTP 403 with that message.

### Auth key – invalid allowed IP
<a id="account-key-invalid-ip"></a>

A key with an invalid IP range is refused with the reason

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/auth_keys/index`.
3. Add an auth key with the allowed IP `999.0.0.0/99`.

**Expected:** the key is not created and the message says the IP range is invalid.

**Seeded data:** Through the API the key is refused, but only with "Could not add auth_key" (see Recommendation 3).

### Auth key – expiration in the past
<a id="account-key-expired"></a>

A key whose expiration date is already past

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/auth_keys/index`.
3. Add an auth key with the comment `QA expired` and the expiration `2020-01-01`.
4. Use it to list events.

**Expected:** the key is refused at creation (the date is in the past), or created and clearly marked as expired; using it fails.

**Seeded data:** Through the API the key is created without warning; using it fails with "Authentication failed…" (HTTP 403).

### Auth keys – only my keys
<a id="account-key-own-only"></a>

A user only sees their own auth keys

1. Log in to MISP as `user` of the organisation `QA-Org-B`.
2. Go to `/auth_keys/index`.
3. Look at the keys listed.

**Expected:** only the keys of `qa-user-b@qa-org-b.test` are listed.

**Seeded data:** Through the API, `qa-user-b` only sees its own keys.
