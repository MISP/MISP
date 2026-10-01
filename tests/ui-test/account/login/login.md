# MISP Web UI – Account – Login Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Login – wrong password](#account-login-wrong) | |
| 2 | [Login – brute force protection](#account-login-bruteforce) | |
| 3 | [Logout – session closed](#account-logout) | |

---


# E2E Tests

### Login – wrong password
<a id="account-login-wrong"></a>

A wrong password does not say whether the account exists

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/users/login`.
3. Log out.
4. Log in with `qa-user-b@qa-org-b.test` and a wrong password.
5. Log in with `nobody@qa.test` and a wrong password.

**Expected:** both attempts show the same generic message, so nobody can learn which emails have an account.

### Login – brute force protection
<a id="account-login-bruteforce"></a>

After 5 failed logins the account is blocked for 5 minutes, even with the right password

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/users/login`.
3. Log out.
4. Log in 5 times with `qa-user-b@qa-org-b.test` and a wrong password.
5. Log in with the right password.
6. Wait 5 minutes and log in with the right password.

**Expected:** after 5 failures, even the right password shows "You have reached the maximum number of login attempts. Please wait 300 seconds and try again."; after 5 minutes the login works.

**Seeded data:** Checked on the instance: after 6 failures for `qa-user-b`, the right password gave HTTP 403 with exactly that message (5 entries in the `bruteforces` table until the lock expires).

### Logout – session closed
<a id="account-logout"></a>

After logging out, the previous pages are not reachable

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/events/index`.
3. Open `/events/index`.
4. Log out.
5. Use the browser **Back** button and reload the page.

**Expected:** the login page is shown; no event data is visible.
