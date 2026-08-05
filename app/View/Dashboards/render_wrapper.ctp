<?php
/**
 * Wrapper renderer for the dashboard's Add Widget placement flow.
 *
 * Inputs (set by DashboardsController::renderWrapper):
 *   $widget — array shape consumed by Elements/dashboard/widget/
 *             wrapper.ctp: { widget, instance_id, config, schema,
 *             placeholder, alias, position: {x, y, w, h} }
 *
 * The wrapper element resolves through Cake's themed view path —
 * Themed/<Theme>/Elements/dashboard/widget/wrapper.ctp wins when a
 * theme is active, default Elements/dashboard/widget/wrapper.ctp
 * otherwise. The body container ships as a "Loading…" placeholder;
 * the client's `_renderWidget` POST fills it via /dashboards/
 * renderWidget right after `Grid.addTile` lands.
 */
echo $this->element('dashboard/widget/wrapper', array('widget' => $widget));
