# MISP Web UI – Account – Password Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Password – too short](#account-password-short) | |
| 2 | [Password – long without complexity](#account-password-long) | |
| 3 | [Password – wrong confirmation](#account-password-confirm) | |

---


# E2E Tests

### Password – too short
<a id="account-password-short"></a>

A short password is refused with the rule

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/users/view/me`.
3. Open **My Profile** → change password.
4. Type `short` as new password, confirm and save.

**Expected:** the password is refused and the message says the length rule (e.g. "Password length requirement not met.").

**Seeded data:** Through the API, `change_pw` with `short` is refused, but only with "Could not change_pw User" (see Recommendation 3).

### Password – long without complexity
<a id="account-password-long"></a>

A long password without digits or upper case

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/users/view/me`.
3. Open **My Profile** → change password.
4. Type a 19-letter lower-case password, confirm and save.
5. Change it back to your previous password.

**Expected:** the password is accepted (MISP accepts any password of 16 characters or more), so this is the expected rule, not a bug.

**Seeded data:** Through the API, `qa-user-b` could set a 19-letter lower-case password ("Password Changed."); the original password was restored right after.

### Password – wrong confirmation
<a id="account-password-confirm"></a>

The confirmation must match the new password

1. Log in to MISP as `user` of the organisation `ADMIN`.
2. Go to `/users/view/me`.
3. Open **My Profile** → change password.
4. Type two different passwords in the new password and confirmation fields and save.

**Expected:** nothing is changed and the message says the passwords do not match.
