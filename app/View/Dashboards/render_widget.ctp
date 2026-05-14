<?php
/**
 * Renderer dispatcher for the dashboard.
 *
 * Inputs (set by DashboardsController::renderWidget):
 *   $widget       — the widget class instance (for $render, $title etc)
 *   $data         — return value of $widget->handler($user, $config)
 *   $renderer     — string, the renderer name to load
 *   $config       — the resolved widget config dictionary
 *   $instance_id  — stable id for the widget instance
 *
 * Renderers live at View/Elements/dashboard/Widgets/<Name>.ctp.
 * Each emits the widget *body* HTML; the surrounding wrapper (border,
 * title bar, action buttons) is rendered by the index view.
 */
if (!preg_match('/^[A-Za-z0-9_-]+$/', $renderer)) {
    echo '<div class="misp-widget-error">' . __('Invalid renderer name.') . '</div>';
    return;
}
$elementPath = 'dashboard/Widgets/' . $renderer;
echo $this->element($elementPath, [
    'data'        => $data,
    'config'      => $config,
    'widget'      => $widget,
    'instance_id' => $instance_id,
]);
