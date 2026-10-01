# MISP Web UI – Attribute Add – Form Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Attribute add – ip-dst](#attribute-add-ip) | |
| 2 | [Attribute add – invalid IP](#attribute-add-invalid-ip) | |
| 3 | [Attribute add – invalid md5](#attribute-add-invalid-md5) | |
| 4 | [Attribute add – port out of range](#attribute-add-invalid-port) | |
| 5 | [Attribute add – duplicate](#attribute-add-duplicate) | |
| 6 | [Attribute add – duplicate after normalisation](#attribute-add-duplicate-normalised) | |
| 7 | [Attribute add – domain normalisation](#attribute-add-domain-normalised) | |
| 8 | [Attribute add – internationalised domain](#attribute-add-idn) | |
| 9 | [Attribute add – with First Seen](#attribute-add-first-seen) | |
| 10 | [Attribute add – First Seen after Last Seen](#attribute-add-seen-order) | |
| 11 | [Attribute add – types limited by category](#attribute-add-category-types) | |
| 12 | [Attribute add – on a published event](#attribute-add-published-event) | |
| 13 | [Attribute add – warninglist hit](#attribute-add-warninglist) | |
| 14 | [Attribute add – correlation disabled](#attribute-add-no-correlation) | |
| 15 | [Attribute add – emoji in the comment](#attribute-add-emoji-comment) | |

---


# E2E Tests

### Attribute add – ip-dst
<a id="attribute-add-ip"></a>

Adding a simple ip-dst attribute for IDS

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute ip` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.30` in **Value**.
6. Tick **For IDS**.
7. Click **Add Attribute** to save.

**Expected:** the event opens on the Attributes tab and shows `198.51.100.30` as `ip-dst` with **IDS** on.

### Attribute add – invalid IP
<a id="attribute-add-invalid-ip"></a>

An invalid IP address is refused and the typed value is kept

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute invalid ip` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `999.1.1.1` in **Value**.
6. Click **Add Attribute** to save.

**Expected:** the attribute is not saved, the message "IP address has an invalid format." is shown, and the form stays open with `999.1.1.1` still filled in.

### Attribute add – invalid md5
<a id="attribute-add-invalid-md5"></a>

A hash with the wrong length is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute invalid md5` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Payload delivery`, in **Type** select `md5`, and type `abc123` in **Value**.
6. Click **Add Attribute** to save.

**Expected:** the attribute is not saved and the message "Checksum has an invalid length or format (expected: 32 hexadecimal characters)…" is shown.

### Attribute add – port out of range
<a id="attribute-add-invalid-port"></a>

An ip-dst|port value with a port above 65535 is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute invalid port` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst|port`, and type `198.51.100.31|70000` in **Value**.
6. Click **Add Attribute** to save.

**Expected:** the attribute is not saved and the message "Port numbers have to be integers between 1 and 65535." is shown.

### Attribute add – duplicate
<a id="attribute-add-duplicate"></a>

The same attribute twice in one event is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute duplicate` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `domain`, and type `qa-dup.example` in **Value**.
6. Click **Add Attribute** to save.
7. Click **Add Attribute**.
8. In **Category** select `Network activity`, in **Type** select `domain`, and type `qa-dup.example` in **Value**.
9. Click **Add Attribute** to save.

**Expected:** the second attribute is not saved and the message "A similar attribute already exists for this event." is shown.

### Attribute add – duplicate after normalisation
<a id="attribute-add-duplicate-normalised"></a>

A domain that only differs by case and a trailing dot is a duplicate

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute duplicate case` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `domain`, and type `qa-case.example` in **Value**.
6. Click **Add Attribute** to save.
7. Click **Add Attribute**.
8. In **Category** select `Network activity`, in **Type** select `domain`, and type `QA-Case.Example.` in **Value**.
9. Click **Add Attribute** to save.

**Expected:** the second attribute is refused with "A similar attribute already exists for this event.", because MISP stores domains in lower case without the trailing dot.

### Attribute add – domain normalisation
<a id="attribute-add-domain-normalised"></a>

A domain in upper case with a trailing dot is stored normalised

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute domain normalised` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `domain`, and type `QA-Norm.Example.` in **Value**.
6. Click **Add Attribute** to save.

**Expected:** the attribute is saved and shown as `qa-norm.example`.

### Attribute add – internationalised domain
<a id="attribute-add-idn"></a>

A domain with non-ASCII characters is stored in punycode

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute idn` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `domain`, and type `bücher.example` in **Value**.
6. Click **Add Attribute** to save.

**Expected:** the attribute is saved and shown as `xn--bcher-kva.example`.

### Attribute add – with First Seen
<a id="attribute-add-first-seen"></a>

Saving an attribute with a First Seen date does not trigger a CSRF error (same hidden-field pattern as Bug 28 and Bug 4)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute first seen` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.32` in **Value**.
6. Set **First Seen (UTC)** to `2026-09-01 10:00`.
7. Click **Add Attribute** to save.

**Expected:** no "You have tripped the cross-site request forgery protection of MISP" page; the attribute is saved with the First Seen `2026-09-01 10:00`.

### Attribute add – First Seen after Last Seen
<a id="attribute-add-seen-order"></a>

An attribute whose First Seen is later than its Last Seen is refused

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute seen order` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.33` in **Value**.
6. Set **First Seen (UTC)** to `2026-10-01 10:00` and **Last Seen (UTC)** to `2026-01-01 10:00`.
7. Click **Add Attribute** to save.

**Expected:** the attribute is not saved and a clear message says that First Seen must be before Last Seen; no error page.

### Attribute add – types limited by category
<a id="attribute-add-category-types"></a>

The Type list only offers types allowed for the chosen category

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute category types` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Financial fraud`.
6. Open the **Type** list.

**Expected:** the **Type** list offers financial types (e.g. `iban`, `bic`) and does not offer `ip-dst`.

### Attribute add – on a published event
<a id="attribute-add-published-event"></a>

Adding an attribute to a published event unpublishes it

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute published` with **Add Event** and stay on its detail page.
4. Click **Publish Event** and confirm.
5. Click **Add Attribute**.
6. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.34` in **Value**.
7. Click **Add Attribute** to save.

**Expected:** the attribute is saved and the event is now shown as Unpublished.

### Attribute add – warninglist hit
<a id="attribute-add-warninglist"></a>

A value present in an enabled warninglist shows a warning

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Go to `/warninglists/index`, search for `List of known IPv4 public DNS resolvers` and click **Enable**.
4. Go to `/events/index`.
5. Create an event `QA attribute warninglist` with **Add Event** and stay on its detail page.
6. Click **Add Attribute**.
7. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `8.8.8.8` in **Value**.
8. Click **Add Attribute** to save.
9. Go to `/warninglists/index` and click **Disable** on `List of known IPv4 public DNS resolvers`.

**Expected:** the attribute is saved and is marked with a warninglist hit naming `List of known IPv4 public DNS resolvers`.

### Attribute add – correlation disabled
<a id="attribute-add-no-correlation"></a>

An attribute with correlation disabled does not correlate with other events

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA correlation off 1` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.35` in **Value**.
6. Click **Add Attribute** to save.
7. Go to `/events/index`.
8. Create an event `QA correlation off 2` with **Add Event** and stay on its detail page.
9. Click **Add Attribute**.
10. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.35` in **Value**.
11. Tick **Disable Correlation**.
12. Click **Add Attribute** to save.

**Expected:** `QA correlation off 2` does not list `QA correlation off 1` in **Related Events**, and its attribute shows no correlation.

### Attribute add – emoji in the comment
<a id="attribute-add-emoji-comment"></a>

An attribute comment with an emoji is saved without error (regression test for Bug 5)

1. Log in to MISP as `site-admin`.
2. Go to `/events/index`.
3. Create an event `QA attribute emoji` with **Add Event** and stay on its detail page.
4. Click **Add Attribute**.
5. In **Category** select `Network activity`, in **Type** select `ip-dst`, and type `198.51.100.60` in **Value**.
6. Type `QA comment 🚀` in **Contextual Comment**.
7. Click **Add Attribute** to save.

**Expected:** no "An Internal Error Has Occurred." page; the attribute is saved and its comment is shown as `QA comment 🚀`.
