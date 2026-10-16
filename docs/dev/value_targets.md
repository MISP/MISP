# Analyst data and collections on attribute values

From 3.0 on, notes, opinions, relationships and collection elements can point at
an **attribute value**: a row of the `attribute_values` dictionary
([attribute_values.md](attribute_values.md)), not only at events, attributes,
objects and the other UUID-addressed types. A value has no uuid. It is addressed
by the SHA-256 of its text, which is the same on every instance, connected or
not.

The short version:

- The target type decides the column. `AttributeValue` is addressed by
  `*_sha256`; every other type keeps `*_uuid`. Exactly one of the two is filled.
- The address is the SHA-256 over the value's stored text, as 64 lowercase hex
  characters.
- The value text never travels with analyst data or collections, and is never
  added to the dictionary from them. A reference resolves on an instance once a
  visible attribute holds the value.
- A MISP older than 3.0 never receives value-addressed rows, and a copy coming
  from one never removes them.

---

## 1. The address map

| Table | UUID column | SHA-256 column |
|---|---|---|
| `notes`, `opinions` | `object_uuid` | `object_sha256` |
| `relationships` (source end) | `object_uuid` | `object_sha256` |
| `relationships` (target end) | `related_object_uuid` | `related_object_sha256` |
| `collection_elements` | `element_uuid` | `element_sha256` |

- The `*_sha256` columns are `varchar(64)` ascii, nullable, indexed; the uuid
  columns became nullable. `collection_elements` has
  `UNIQUE (element_sha256, collection_id)` beside the old
  `UNIQUE (element_uuid, collection_id)`.
- `AnalystData::SHA256_TARGETS` lists the SHA-256-addressed types (only
  `AttributeValue`). `AnalystData::addressColumn($type, $end)` gives the
  column for a type and an end (`object`, `related_object`, `element`); use it
  instead of naming a column.
- Validation (`validAddress`, `AnalystData::addressError()`): the type's column
  must be well formed (a uuid, or `/^[0-9a-f]{64}$/`) and the other one empty.
  Each relationship end is checked on its own; a relationship cannot point at
  its own source.
- **Hex is lowercased** on save and in every lookup
  (`AnalystData::normaliseAddress()`). MySQL compares the ascii columns
  case-insensitively, PostgreSQL does not: without the lowercasing the unique
  key would keep `ABC…` and `abc…` apart there.

## 2. Computing an address

The hash is over the value **as MISP stores it**: after refanging and trimming,
with domains, hostnames, hashes and e-mail addresses lowercased. That is the
`value` an attribute has in the API output, not what a user typed.

```python
import hashlib
address = hashlib.sha256(attribute['value'].encode('utf-8')).hexdigest()
```

- A composite attribute (`domain|ip`, `filename|sha256`, …) holds two values:
  hash each half on its own.
- Case variants (`Evil.com`, `evil.com`) are different values with different
  addresses.
- `GET /values/view?value=<text>` returns the stored value with its `sha256`, and
  `GET /values/view/sha256:<hex>` confirms an address. Both answer 404 for a
  value the user cannot see.

## 3. REST

**Analyst data**

| Call | Notes |
|---|---|
| `POST /analystData/add/<Note\|Opinion\|Relationship>/<hex>` | A 64-hex address with no type is an `AttributeValue`; `/<hex>/AttributeValue` says so explicitly. The address may also come as `object_sha256` in the body |
| Relationship body `related_object_type: AttributeValue`, `related_object_sha256: <hex>` | Either end, or both, may be a value |
| `GET /analystData/viewForObject/AttributeValue/<hex>` | The notes, opinions and relationships on the value |
| `/analystData/index/<Type>` with `object_sha256` | One hex or a list, in the body or as a named parameter |

**Collections**

| Call | Notes |
|---|---|
| `POST /collectionElements/addElementToCollection/AttributeValue/<hex>` `{"collection_id"}` | Attach. A second attach of the same value answers that it is already in the collection |
| `POST /collectionElements/add/<collection_id>` `{"element_type": "AttributeValue", "element_sha256"}` | The same, by body. `value` (the text) may stand in for `element_sha256`: the server hashes it and keeps only the hash |
| `Collection.CollectionElement[]` on `/collections/add` and `/collections/edit` | Nested elements with `element_sha256` |
| `GET /collections/getCollectionsForElement/AttributeValue/<hex>`, `POST /collections/getCollectionsForElements/AttributeValue` `{"uuids": [<hex>, …]}` | The collections holding a value, under each collection's own ACL |

## 4. Visibility

- **A value target resolves** for a user when the dictionary holds the value and
  at least one attribute holding it is visible to that user
  (`AnalystData::visibleValuesBySha256()`). Site admins need a holder too: a
  value held only by deleted attributes, or by none, is unresolved for everyone.
- **Missing, unheld and invisible are one answer.** Resolving a collection
  element or the far end of a relationship cannot tell them apart, so a guessed
  hash reveals nothing.
- **Notes, opinions, relationships and collection elements accept any
  well-formed hash**, as they accept any uuid: annotating or collecting a value
  the instance does not hold yet is allowed. A collection element shows the
  value's text to readers who can see the value, and its SHA-256 to everyone
  else.
- **The analyst data's own ACL decides who sees it**, as for uuid targets:
  `viewForObject` and the index list rows by their distribution and sharing
  group, whatever the value's visibility. A relationship's resolved end
  (`related_object`) is `{"AttributeValue": {"value", "sha256"}}` when the
  value is visible to the reader, empty otherwise; it never carries the value's
  id.

## 5. Sync

The rule: a MISP older than 3.0 cannot store these rows, so it never gets them,
and what it sends back never removes them. Between 3.x instances everything
travels.

**Which peer is older than 3.0**

- On **push** and **pull**, the remote's version comes from `/servers/getVersion`
  (`ServerSyncTool::FEATURE_VALUE_TARGETS`: 3.0.0 or later).
- When a peer **pulls from us** or **pushes to us**, its version comes from the
  request: `SyncTool::requesterMispVersion()` reads `User-Agent: MISP <x.y.z> - #…`
  (and the `MISP-version` header older peers sent). `AppController` records it as
  `CurrentRequesterMispVersion`; `SyncTool::valueTargetsWithheld()` is true below
  3.0.0.
- A request that does not identify as a MISP (PyMISP, scripts, browsers) is
  never filtered.
- This is about compatibility, not access: a sync user can claim any version,
  and the rows are shared with it by their distribution either way.

**What changes for a peer older than 3.0**

| Path | Behaviour |
|---|---|
| Push | `AnalystData::withoutValueTargets()` and `Collection::withoutValueElements()` drop value-addressed rows and elements; the collection itself still goes |
| Serving a pull | `AnalystData::beforeFind` adds `<end>_sha256 IS NULL` to every analyst data read in that request: `indexMinimal`, `index` by uuid, and the analyst data nested in `/events/view`. The collection index leaves value elements out |
| Capturing from it | Value-addressed analyst data is refused ("not accepted from a MISP older than 3.0"), children included. A newer copy of a collection is taken, but local value elements are kept instead of being removed as absent, and incoming ones are dropped |

The capture methods take a `$fromPre30` flag: the pulls pass it from the remote's
version, and `null` (push receive) lets the requester's version decide.

**Nothing value-addressed is nested in an event.** A note on a value targets no
event child. A relationship from an attribute to a value is nested under the
attribute in `/events/view`, which is why the serving filter covers that path.

## 6. Code map

| Path | What |
|---|---|
| `app/Model/AnalystData.php` | Address map, validation, `existingTargets()`, `visibleValuesBySha256()`, `countForObjectRecursive()`, `withoutValueTargets()`, `isValueAddressed()`, `beforeFind` filter, capture |
| `app/Model/Relationship.php` | Both ends, the self-reference rule, `getRelatedElement()`, inbound relationships |
| `app/Model/Behavior/AnalystDataBehavior.php` | `fetchForSha256s()` |
| `app/Model/CollectionElement.php` | Type list, `assertTargetsUsable()`, `captureElements()` |
| `app/Model/Collection.php` | `withoutValueElements()`, `captureCollection()` |
| `app/Model/AttributeValue.php` | `findBySha256()` |
| `app/Lib/Tools/SyncTool.php`, `ServerSyncTool.php` | Peer version |
| `app/Controller/AnalystDataController.php`, `CollectionElementsController.php`, `CollectionsController.php` | REST routing by type |
| `app/Lib/Migration/Migrations/` | `value_address_columns` |

Tests: `ValueAddressTest` (validation), `AnalystDataValueTargetDbTest` (resolution
and ACL, needs `ATTRIBUTE_VALUE_DB_TESTS=1`), `CollectionElementCaptureTest`,
`CollectionCaptureTest`, `CollectionPullTest`, `CollectionPushTest`,
`SyncAnalystDataCaptureTest`, `SyncAnalystDataPushTest`,
`SyncAnalystDataWithheldTest`, `ServerSyncVersionCompatibilityTest`.
