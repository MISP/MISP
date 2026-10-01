# MISP Web UI – Admin Users – Site Admin Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [User add – email already used](#admin-user-duplicate-email) | |
| 2 | [User add – same email in upper case](#admin-user-email-case) | |
| 3 | [User add – invalid email](#admin-user-invalid-email) | |
| 4 | [User disable](#admin-user-disable) | |
| 5 | [User role change – Read Only](#admin-user-role-read-only) | |

---


# E2E Tests

### User add – email already used
<a id="admin-user-duplicate-email"></a>

Creating a user with an email that already has an account

1. Log in to MISP as `site-admin`.
2. Go to `/admin/users/index`.
3. Click **Add User**, type `qa-user-a@admin.test`, choose an organisation and a role, and save.

**Expected:** the user is not created and the message says the email is already used.

**Seeded data:** Through the API it is refused, but only with "Could not add User" (see Recommendation 3).

### User add – same email in upper case
<a id="admin-user-email-case"></a>

An email that only differs by case is the same account

1. Log in to MISP as `site-admin`.
2. Go to `/admin/users/index`.
3. Click **Add User**, type `QA-USER-A@ADMIN.TEST` and save.

**Expected:** the user is not created (the email already exists).

**Seeded data:** Through the API it is refused ("Could not add User").

### User add – invalid email
<a id="admin-user-invalid-email"></a>

Creating a user with an invalid email

1. Log in to MISP as `site-admin`.
2. Go to `/admin/users/index`.
3. Click **Add User**, type `not-an-email` and save.

**Expected:** the user is not created and the message says the email is invalid.

**Seeded data:** Through the API it is refused, but only with "Could not add User".

### User disable
<a id="admin-user-disable"></a>

A disabled user cannot log in nor use their API key

1. Log in to MISP as `site-admin`.
2. Go to `/admin/users/index`.
3. Click **Edit** on `qa-user-a@admin.test`, tick **Disable this user account** and save.
4. Log out and try to log in as `qa-user-a@admin.test`.
5. Log back in as `site-admin` and enable `qa-user-a@admin.test` again.

**Expected:** while disabled, the login and the API key of `qa-user-a` are refused; after enabling, both work again.

**Seeded data:** Through the API: disabled → its API key got HTTP 403; enabled again → HTTP 200.

### User role change – Read Only
<a id="admin-user-role-read-only"></a>

Changing a user to Read Only removes the right to create

1. Log in to MISP as `site-admin`.
2. Go to `/admin/users/index`.
3. Click **Edit** on `qa-user-a@admin.test`, set **Role** to `Read Only` and save.
4. Log in as `qa-user-a@admin.test` and try **Add Event**.
5. Log back in as `site-admin` and set the role back to `User`.

**Expected:** as Read Only, **Add Event** is not offered or refused with "You do not have permission to use this functionality."

**Seeded data:** Through the API, with the role `Read Only`, `qa-user-a` creating an event got HTTP 403 with that message; the role was set back to `User`.
