# MISP Web UI – Attribute Index – Search Tests  <img src="https://hdoc.csirt-tooling.org/uploads/5381daed-33a6-4785-b452-101cae85291f.png" width="50">

 <a id="navigation"></a>
 
 
Roles: 
- user
- site-admin
- org-admin


## E2E UI Tests

| # | Test | Owner | 
|---| ---- | ----- |
| 1 | [Attribute list – filter by value](#attribute-index-filter-value) | |
| 2 | [Attribute list – filter by type](#attribute-index-filter-type) | |
| 3 | [Attribute list – special characters](#attribute-index-special-chars) | |

---


# E2E Tests

### Attribute list – filter by value
<a id="attribute-index-filter-value"></a>

The Attributes list finds the same value in several events

1. Log in to MISP as `site-admin`.
2. Go to `/attributes/index`.
3. Make sure two events contain the attribute `198.51.100.51` (see the test "Attribute delete – correlation removed" before its last step).
4. Type `198.51.100.51` in **Filter by attribute value**.
5. Press Enter.

**Expected:** the list shows the attribute in both events, with their **Event ID**.

### Attribute list – filter by type
<a id="attribute-index-filter-type"></a>

The Attributes list filtered on one type

1. Log in to MISP as `site-admin`.
2. Go to `/attributes/index`.
3. Click **More filters**.
4. In **Type**, select `ip-dst`.
5. Apply the filter.

**Expected:** only `ip-dst` attributes are listed.

### Attribute list – special characters
<a id="attribute-index-special-chars"></a>

Searching attributes with special characters

1. Log in to MISP as `site-admin`.
2. Go to `/attributes/index`.
3. Type `'%"<b>` in **Filter by attribute value**.
4. Press Enter.

**Expected:** the list is empty or shows only matching attributes, the search text is shown as typed, and no error page is shown.
