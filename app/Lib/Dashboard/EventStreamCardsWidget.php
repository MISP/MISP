<?php
require_once 'EventStreamWidget.php';

/**
 * Event Stream — card layout (dashboard v2, analyst track — AD-W6 / AD-08).
 *
 * A pure-additive sibling of EventStreamWidget: it inherits the ENTIRE
 * proven data layer verbatim — handler(), $schema, $params, and every
 * canonical filter (tags, orgs w/ match_via + per-entry negate, published,
 * threat_level, analysis, sharing_group, galaxy_cluster) — so the same
 * toolbar bulk-edit drives it for free. The only difference is the render
 * kind: it emits the `EventCards` renderer (flat, reverse-chronological
 * detail cards) instead of the tabular `Index`. Read-only by design
 * (AD-08 Fork B): no in-body controls; filtering / scoping happens on the
 * dashboard toolbar, exactly as for the parent.
 *
 * No cache (inherited): fetchEvent is per-user ACL'd and the view is
 * near-live (autoRefreshDelay = 5, inherited), so AD-04's per-org aggregate
 * cache does not apply here.
 *
 * Subclassing is the established in-tree pattern for a render-only variant
 * (OrgsContributorLastMonthWidget / OrgsUsing* extend OrgsContributorsGeneric);
 * Dashboard::loadWidget loads widgets by filename.
 */
class EventStreamCardsWidget extends EventStreamWidget
{
    public $title = 'Event Card Stream';
    public $render = 'EventCards';
    public $description = 'Monitor incoming events as detailed cards (threat level, organisation, tags and attribute count at a glance). Same filters as the Event Stream, driven by the dashboard toolbar bulk-edit.';
}
