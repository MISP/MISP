# Workspace and saved graphs — Guide

An investigation rarely stays inside one event. The **workspace** lets you
gather the records you read, from any page, into one place, see how they
connect, keep a picture of it, and turn what you found into an event. This
guide is for analysts; the last section lists the REST calls behind it.

The workspace is part of the **Overmind** theme. The classic interface keeps
its **Add to collection** dialog, which adds a record to a collection of your
organisation but has no workspace.

## 1. Three terms

| Term | What it is |
|---|---|
| **Collection** | The record: a named set of members (events, galaxy clusters, attributes, objects, values) with a type, a description and a distribution, shared like any other record. |
| **Workspace** | Only the collection you are working in right now. "Add to workspace" adds to it; **No workspace** means you have none. |
| **Saved graph** (or just *graph*) | A drawing you keep: where the nodes sit, which were kept from a pivot, which are hidden. It is stored on an event, a galaxy cluster or a collection. |

Any collection you may edit can be your workspace. You can change it as often
as you like; nothing is copied when you do.

## 2. Your workspace

The **navbar chip** shows the collection you are working in, with its number
of members, or says **No workspace**.

- Click it to open the workspace beside the page, to switch to another
  collection, or to start a new one.
- Every browser tab follows a switch: pick another workspace in one tab and
  the others change with it.
- The workspace can be docked to the left or the right of the page, or
  undocked into a window.

To start a collection, choose **New collection…**, give it a name and press
**Create**. It starts as:

- shared with **Your organisation only**,
- of type **Research**,
- with **Make it my workspace** ticked.

A line under the name states these defaults; **change** lets you pick another
type or distribution before you create it.

To make a collection you already have your workspace, open it from
**Collections** and press **Make it my workspace**. The collection cards of
events and galaxy clusters, and the **Saved graphs** card, offer the same.

You need the right to modify (`perm_modify`) to have a workspace.

## 3. Adding records

Events, galaxy clusters, attributes, objects and values carry one **Add to
workspace** control. A click adds the record to your workspace and a tick
(**In workspace ✓**) then says it is there. The caret then offers **Show in the
dock** and **Remove from workspace**.

The control's caret offers more:

- **Add to another collection…** adds the record to a collection of your
  organisation without changing your workspace.
- **New collection with this…** starts a new collection that already holds the
  record.

On the events, attributes, objects and galaxy clusters indexes, select rows and
use the selection bar's workspace button to add them all.

The value batch review has the same control. It can hand over only the values
you opened (**The N opened**) or the whole batch (**All N in the batch**).

When you add a value, a short note appears if it is held in MISP only by
events shared more narrowly than the collection: people who can see the
collection will then see the value. Check who the collection is shared with
before you keep it.

Each member can say **why** it is there, in one line. The working view asks for
it when a record arrives (**Why?**), and **Say why…** or **Edit why…** in a
member's actions changes it later.

## 4. The working view

The **dock** beside any page, and the **Pivot Explorer** tab of a collection's
page, are the same view. It draws the members of the collection, and shows a
list beside the graph. The buttons above it choose **Graph**, **Both** or
**List**.

- **Placement.** New members are placed for you. If a saved graph lays out your
  workspace, members sit where you put them; otherwise the layout is automatic.
  A collection that is not your workspace opens with every member and an
  automatic layout.
- **The list.** Sort and filter by value, type, comment, event, who, when and
  why. **Show** narrows it to **Members**, **Not in MISP yet**, what is **On the
  graph, not in the collection**, or what is **Hidden on this graph**. Select
  rows to remove them, add them or make an event of them.
- **Layout.** Dragging nodes marks the layout as changed: **Layout changed
  here. Positions are not saved until you save them.** Press **Save layout** to
  keep it, or **Discard**. With no saved graph behind the workspace, **Save as
  graph…** keeps the layout as a new saved graph on the collection, which then
  lays the workspace out. **Save as new graph…** keeps another. Only the
  organisation that owns a graph can save it; if it was saved somewhere else
  since the view opened you are offered **Save my layout over it** or
  **Reload**. Records you add are never at risk: they go to the collection as
  they land.
- **Hiding.** **Hide on this graph** in a member's actions takes the node off
  the drawing without removing the member from the collection. It is written at
  once and shown under **Hidden on this graph**, where **Show on this graph**
  brings it back. **Remove from graph** drops a node that is on the graph but
  not in the collection.
- **Why?** A record added from another page lands with a **Why?** prompt:
  one line on why it joins the workspace.
- **Copy as my collection…** makes a collection of your own from what is
  drawn.

### Members MISP does not hold

A collection can also hold what MISP has no record of. These members are
marked **not in MISP yet**:

- **Values** with no attribute behind them. A value member keeps its own text.
- **Standalone objects**: an object a module answered, or one you make
  yourself. Its values stay inside it and have no value page and no
  correlation.

A standalone object opens from the caret on its row, or **Open** in its menu.
**New object from a template…** (in **More actions on the members**) lets you
pick a template, fill in its fields and press **Add object**; the template's
requirements are checked before it is added.

Members that came from a module say so (for example *from a module on a
value*).

## 5. Publishing a shared collection

A collection shared with **Your organisation only** has nothing to publish.
A collection shared wider keeps its changes in-house until someone publishes
them, as an event does. Until then partners keep the version they last
received. A change is a member added or removed, a change to the collection
itself, or a saved graph or link between members that your organisation drew on
it. A graph or link kept to your organisation never leaves this instance, so
saving one changes nothing partners would receive.

The collection page shows where it stands:

| Pill | Meaning |
|---|---|
| **Published** | Partners hold this collection as it is. |
| **N changes not yet shared** | Changes wait for someone who can publish. |
| **N changes waiting for a publisher** | The same, for someone who cannot publish. |
| **Unpublished** | The collection was withdrawn by hand. |

The collection list shows the same as one glyph per row, as the event list
does: a tick when published, a dashed clock when it changed since it was
published, a disk when it is unpublished, a dash when it is shared with your
organisation only. Its tooltip gives the date and the changes waiting. Beside
the members, the list counts the saved graphs you can see on each collection.

To release it:

1. Press **Review and publish**. The review lists the members added and
   removed since the last publish, the saved graphs and the links that go with
   them, and values held only in narrower events.
2. Say how far the investigation went under **Still ongoing?**: **Ongoing**
   (partners see it as still in progress) or **Completed**.
3. Confirm.

The members, the saved graphs and the links between them go out together as
soon as it is published, to every server collections are pushed to.
**Unpublish collection** withdraws it again; partners keep what they received.

Publishing takes the same right as publishing an event (`perm_publish`) and
the right to edit the collection. Without it your changes wait for a
publisher.

## 6. From findings to an event

Select members in the working view, or open the menu **More actions on the
members**, to make an event of them:

| Action | What it does |
|---|---|
| **Create an event with what is not in MISP yet…** | Makes a new event of the values and objects MISP does not hold. |
| **Create an event from the selection…** | Makes a new event of the selected members. |
| **Add the selection to an event…** | Adds the selected members to an event you may edit. |

A dialog walks through **What goes in**, **Which event** and **Review**. You
can edit the type, category and **For IDS** flag of each attribute before it is
made. A new event is unpublished and owned by your organisation: nothing leaves
the instance until you publish it. When the event is made of the whole
collection, the dialog also asks **Still ongoing?** (**Initial**, **Ongoing**,
**Completed**).

What happens to each member:

- A value or object MISP does not hold becomes an attribute or an object of the
  event, and takes the place of its member: the collection holds the new record
  instead.
- An attribute or object from another event is copied, and the copy is never
  shared wider than its source. The review says so (for example *shared as
  Your organisation only, as its source*).
- A galaxy cluster becomes a galaxy tag on the event.
- An event is linked to the new event with a **related-to** relationship.
- Values held only in narrower events are listed: everyone the event reaches
  will see them.

At most 500 members go into one event at once. Making an event takes the right
to add and modify events; the galaxy tags and the links need the tagging and
analyst data rights, and the review says when one is left out for lack of them.

## 7. Saved graphs

A saved graph is a picture you keep. You make one in a Pivot Explorer with
**Save as graph…**, and it is kept on an event, a galaxy cluster or a
collection, shared like any other record. Making one takes the right to add and
the analyst data right (`perm_add`, `perm_analyst_data`).

Where to find them:

- **Event and galaxy cluster pages** have an **In investigations** card: the
  collections that hold the record, then the graphs kept on it.
- **Collection pages** have a **Saved graphs** card.
- **Analyst Data → Saved graphs** (`/analystData/index/Graph`) lists them all.
  The graph that lays out your workspace carries a **Workspace** mark.

Hover a thumbnail for a preview and double-click a row to open the graph. On
the **Saved graphs** card of a collection you may edit, a graph can be chosen to
lay your workspace out (**Make this collection my workspace, laid out by this
graph**).

A saved graph keeps its own nodes and changes only when someone saves it:
positions, nodes kept from a pivot, nodes removed, links hidden. A graph of a
collection that has grown since says so: **N members joined the collection
since**.

A graph from another organisation is read-only. **Fork** it to get a copy that
your organisation owns, holding the nodes you can see and shared like the
record it is forked onto.

## 8. Sharing

A graph starts shared like the record it is kept on. In its sharing choice,
**(like the collection)** marks that default. Choosing something wider warns
you: *Wider than this collection: people who can’t see it will see which
records are in it.* (the same for events and galaxy clusters, with the record
named).

Widening a collection offers to bring what is drawn on it along. When you save
the collection with a wider distribution, **Share these too** lists the saved
graphs and the **Links between members** that reach fewer people; tick the ones
that should take the collection's new sharing.

## 9. Older MISP instances

Synchronisation of collections is described for developers in
`docs/dev/collection_sync.md`. For analysts:

- A MISP older than 3.0 holds only event and galaxy cluster members. It
  receives those and none of the others. The collection itself still goes.
  What it sends back never removes the other members from your copy.
- A 3.0 instance that is not yet able to hold standalone objects receives the
  collection without them.
- A collection shared beyond your organisation and not published since its
  last change is neither sent to partners nor taken by their pulls, as an
  unpublished event. Their instances can still list it, marked unpublished,
  but not its saved graphs or the links between its members. A MISP older
  than 3.0 is not shown it at all. With `MISP.unpublishedprivate` set, only
  your organisation sees it, as with events.
- Who added a member stays inside the collection's organisation; when it was
  added is sent.

## 10. REST API

All calls accept and return JSON. Send your authentication key in the
`Authorization` header, `Accept: application/json` and, for a body,
`Content-Type: application/json`. A collection is named by its uuid (an id works
where the table says so).

### Collections

| Method and path | What it does | Main parameters | Needs |
|---|---|---|---|
| `GET /collections/active` | Your workspace: `{Collection, Graph}` | none | `perm_modify` |
| `POST /collections/active` | Set, or end, your workspace | `collection_uuid` (or `null` to end it), `graph_uuid` (optional: the graph that lays it out; `null` for none) | `perm_modify` |
| `GET /collections/editable` | Collections you may make your workspace, recently used first; `active` is the stored choice | `scope=mine` keeps those you created | `perm_modify` |
| `POST /collections/quickAdd` | Create a collection, optionally make it your workspace and fill it | `name`, `type`, `distribution`, `sharing_group_id`, `description`, `workspace`, `items`, `graph`, `copied_from` | `perm_modify` |
| `GET /collections/index`, `GET /collections/view/<id or uuid>` | List and read collections, with their elements | the usual index filters | any |
| `POST /collections/indexMinimal` | `{uuid: modified}` of the collections you may see | `orgc_name`, `published` (1: published or organisation-only, 0: waiting for a publish) | any |
| `GET /collections/holding/<type>/<address>` | The collections you can see that hold a record, and `active` | type is `Event`, `Attribute`, `Object`, `GalaxyCluster`, `StandaloneObject`, or `Value` (then the address is its SHA-256) | any |
| `GET /collections/getCollectionsForElement/<type>/<address>` | The collections holding one element | | any |
| `POST /collections/getCollectionsForElements/<type>` | The same for many elements, keyed by address | `uuids` | any |
| `GET /collections/publish/<id or uuid>` | The review: what a publish releases | | `perm_modify`, `perm_publish` |
| `POST /collections/publish/<id or uuid>` | Publish | `analysis` (0 Initial, 1 Ongoing, 2 Completed; optional) | `perm_modify`, `perm_publish` |
| `POST /collections/unpublish/<id or uuid>` | Withdraw it from partners until it is published again | | `perm_modify`, `perm_publish` |
| `POST /collections/analysis/<id or uuid>` | Say how far the investigation went | `analysis` | `perm_modify` |
| `GET /collections/shareAlong/<id or uuid>` | What would go along with the collection if it were shared as asked | `distribution`, `sharing_group_id` (for 4) | `perm_modify` |
| `POST /collections/add`, `POST /collections/edit/<id>`, `POST /collections/delete/<id>` | The classic create, edit and delete | | `perm_modify` |

### Members

| Method and path | What it does | Main parameters | Needs |
|---|---|---|---|
| `POST /collection_elements/addItems/<collection>` | Add records | `items` (a list of at most 2000), `description` | `perm_modify` |
| `POST /collection_elements/removeItems/<collection>` | Take records out | `items` | `perm_modify` |
| `POST /collection_elements/describe/<collection>` | Say why a record is held; empty clears it | `item`, `description` (at most 255 characters) | `perm_modify` |
| `POST /collection_elements/contains/<collection>` | Which of these records the collection holds; changes nothing | `items` | `perm_modify` |
| `POST /collection_elements/eventPlan/<collection>` | What a selection would become in an event | `items`, then `event_id` or `distribution` and `sharing_group_id` | `perm_add`, `perm_modify` |
| `POST /collection_elements/toEvent/<collection>` | Make an event of a selection, or add it to one | `items`, then `event` (info, date, distribution, sharing_group_id, threat_level_id, analysis) or `event_id`; `graph` | `perm_add`, `perm_modify` |
| `GET /collection_elements/eventChoices/<collection>` | The events a selection may go into: `{tied, found}` | `q` (an id, a uuid or words of the info) | `perm_add`, `perm_modify` |
| `GET /collection_elements/index/<collection id>` | The elements of a collection | | any |
| `POST /collection_elements/add/<collection id>` | Add one element by type and address | `element_type`, `element_uuid` or `element_sha256` | `perm_modify` |
| `POST /collection_elements/addElementToCollection/<type>/<address>` | Add one record to a collection of your organisation | `collection_id`, `description` | `perm_modify` |
| `POST /collection_elements/delete/<element id>` | Delete one element | | `perm_modify` |

An item is named as one of:

- `{"type": "Event" | "Attribute" | "Object" | "GalaxyCluster" | "StandaloneObject", "uuid": "<uuid>"}`
- `{"type": "Value", "value": "<text>"}` or `{"type": "Value", "sha256": "<hex>"}`
- `{"type": "StandaloneObject", "module": "<module>", "content": {…}}`, an
  object a module answered, or
  `{"type": "StandaloneObject", "template": "<uuid or id>", "attributes": […], "comment": "…"}`,
  an object made from a template
- a `"Type:address"` key, as the answers report them

A value or an answer may add `origin`: `{module, type, value, ran_at}`.

### Saved graphs

| Method and path | What it does | Main parameters | Needs |
|---|---|---|---|
| `GET /analyst_graphs/forTarget/<type>/<uuid>` | The graphs kept on one record, newest first, and the one laying out your workspace | | any |
| `GET /analyst_graphs/editable` | Your organisation's graphs you may edit | `scope=mine` | `perm_add`, `perm_analyst_data` |
| `GET /analyst_graphs/data/<uuid>` | A graph: its document, the records of the nodes you may read, and the edges | | any |
| `GET /analyst_graphs/working/<collection uuid>` | A collection as the working view draws it | `graph` (the uuid of one on this collection) | any |
| `POST /analyst_graphs/edges` | The edges MISP holds between the nodes of a canvas | `nodes` | any |
| `GET /analyst_graphs/thumbnail/<uuid>` | What a thumbnail of the graph draws | | any |
| `POST /analyst_graphs/save/<uuid>` | Replace the document, unless it was saved since `revision` | `revision`, `content` | `perm_add`, `perm_analyst_data` |
| `POST /analyst_graphs/addNodes/<uuid>` | Add records to a graph's document | `items` | `perm_add`, `perm_analyst_data` |
| `POST /analyst_graphs/hideNodes/<uuid>` | Hide nodes, or show them again | `items`, `hidden` (true or false) | `perm_add`, `perm_analyst_data` |
| `POST /analyst_graphs/removeNodes/<uuid>` | Remove records from a graph's document | `items` | `perm_add`, `perm_analyst_data` |
| `POST /analyst_graphs/fork/<uuid>` | Copy a graph for your organisation | `name`, `target` (`{type, uuid}`, to fork it onto another record) | `perm_add`, `perm_analyst_data` |
| `GET /analyst_graphs/export/<uuid>` | A graph as a file to import elsewhere | | any |
| `POST /analyst_graphs/import` | Import graphs from an export | | `perm_add`, `perm_analyst_data` |

The list of graphs of every record is also at `GET /analystData/index/Graph`.

### Examples

Set the active workspace:

```
POST /collections/active
{
  "collection_uuid": "5f1c2a9e-3b7d-4e0a-9d21-6c8e41a7b0f3",
  "graph_uuid": null
}
```

`collection_uuid: null` ends the workspace. The answer is the workspace as the
chip reads it, `{"Collection": {…}, "Graph": {…}}`. A collection you cannot see
answers 404, one you cannot edit 403, and a graph that is not your
organisation's graph on that collection 400.

Create a collection, fill it and make it your workspace:

```
POST /collections/quickAdd
{
  "name": "Phishing wave, March",
  "type": "research",
  "distribution": 0,
  "description": "Everything seen on the March wave",
  "workspace": true,
  "items": [
    {"type": "Event", "uuid": "5f1c2a9e-3b7d-4e0a-9d21-6c8e41a7b0f4"},
    {"type": "Value", "value": "evil.example.com"}
  ]
}
```

Without `type` and `distribution` the collection is `research`, shared with
your organisation only. The answer holds `Collection`, `Graph`, `copied_from`,
`workspace` and `report`, which answers for each item as `addItems` does.

Add items:

```
POST /collection_elements/addItems/5f1c2a9e-3b7d-4e0a-9d21-6c8e41a7b0f3
{
  "items": [
    {"type": "Attribute", "uuid": "5f1c2a9e-3b7d-4e0a-9d21-6c8e41a7b0f5"},
    {"type": "Value", "value": "198.51.100.7"}
  ],
  "description": "Seen in the proxy logs"
}
```

The answer holds `collection_uuid`, `changed`, `element_count`, `Collection`
(as the chip reads it), and the report: `added`, `present` (already held),
`refused` (`index`, `key`, `error`) and `narrower` (values held in MISP only by
events shared more narrowly than the collection), each item by its
`Type:address` key.

Publish a collection:

```
POST /collections/publish/5f1c2a9e-3b7d-4e0a-9d21-6c8e41a7b0f3
{
  "analysis": 1
}
```

The answer is `{"Collection": {…}, "message": "…"}`, the collection as the chip
reads it, with `published`, `last_published`, `analysis` and `withheld`. A
collection shared with your organisation only answers 400: there is nothing to
publish. Without both `perm_publish` and the right to edit the collection the
answer is 403.
