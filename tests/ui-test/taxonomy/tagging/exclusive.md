# MISP Web UI – Taxonomy Tagging – Exclusive Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Exclusive taxonomy – two values on one event](#taxonomy-exclusive-two-tags) | |
| 2 | [Exclusive taxonomy – replace a value](#taxonomy-exclusive-replace) | |
| 3 | [Exclusive taxonomy – event and attribute](#taxonomy-exclusive-event-attribute) | |

---


# E2E Tests

### Exclusive taxonomy – two values on one event
<a id="taxonomy-exclusive-two-tags"></a>

Two values of an exclusive taxonomy (`tlp`) cannot be on the same event

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA exclusive tlp` with **Add Event** and stay on its detail page.
4. Click **Edit Tags**, add `tlp:green` and save.
5. Click **Edit Tags**, add `tlp:red` and save.

**Expected:** `tlp:red` is refused with a message about taxonomy exclusivity, and the event keeps only `tlp:green`.

### Exclusive taxonomy – replace a value
<a id="taxonomy-exclusive-replace"></a>

Replacing a value of an exclusive taxonomy works when the old one is removed first

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA exclusive replace` with **Add Event** and stay on its detail page.
4. Click **Edit Tags**, add `tlp:green` and save.
5. Click **Remove tag** on `tlp:green`.
6. Click **Edit Tags**, add `tlp:red` and save.

**Expected:** the event shows only `tlp:red`, without error.

### Exclusive taxonomy – event and attribute
<a id="taxonomy-exclusive-event-attribute"></a>

A tlp value on an attribute different from the event's tlp value

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA exclusive attribute` with **Add Event** and stay on its detail page.
4. Click **Edit Tags**, add `tlp:green` and save.
5. Add an attribute of type `ip-dst` with value `198.51.100.10`.
6. Add the tag `tlp:red` to this attribute.

**Expected:** the tag is either accepted or refused with a clear message, and the event page shows no error.
