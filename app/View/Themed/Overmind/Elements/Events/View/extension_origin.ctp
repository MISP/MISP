<?php
/**
 * Origin marker for one row / tag / cluster of an extended or extending event
 * view: which event of the merged set it actually comes from.
 *
 * Renders nothing outside such a view (a single-event set has no origin to
 * disambiguate), so a caller can drop it in unconditionally.
 *
 * Parameters:
 *   event_id      int     origin event, normally the row's own event_id
 *   compact       bool    id only, no organisation — for dense tables
 *   only_foreign  bool    stay silent on the viewed event's own content, for
 *                         the inline lists where a marker per item would drown
 *                         the ones that matter (default false)
 *   class         string  extra classes on the badge
 *
 * Read from the view: $extensionEvents (see EventsController::__extensionViewContext)
 */
$extensionEvents = $extensionEvents ?? [];
if (count($extensionEvents) <= 1) {
    return;
}

$originId = (int)($event_id ?? 0);
$origin = $extensionEvents[$originId] ?? null;
$compact = !empty($compact);
if (!empty($only_foreign) && ($origin['role'] ?? null) === 'self') {
    return;
}

$roles = [
    'self' => [
        'icon' => '',
        'title' => __('Belongs to the event you are viewing'),
    ],
    'extension' => [
        'icon' => 'fas fa-code-branch',
        'title' => __('Comes from an event that extends this one'),
    ],
    'extended' => [
        'icon' => 'fas fa-code-merge',
        'title' => __('Comes from the event this one extends'),
    ],
];

if ($origin === null) {
    // An event outside the resolved set — the row still has to say so rather
    // than pass for one of the viewed event's own.
    $palette = $this->ExtensionEventColour->selfPalette();
    $role = ['icon' => 'fas fa-question', 'title' => __('Unknown origin event')];
    $info = '';
} else {
    $palette = $origin['palette'];
    $role = $roles[$origin['role']] ?? $roles['self'];
    $info = (string)$origin['info'];
}

$title = trim($role['title'] . ($info === '' ? '' : ' — ' . $info));
$orgName = $origin['Orgc']['name'] ?? '';
?>
<a href="<?= h($baseurl . '/events/view2/' . $originId) ?>"
   class="badge d-inline-flex align-items-center gap-1 text-decoration-none <?= h($class ?? '') ?>"
   style="background:<?= h($palette['badgeBg']) ?>;
          color:<?= h($palette['badgeText']) ?>;
          border:1px solid <?= h($palette['badgeBorder']) ?>;
          font-weight:600;"
   data-bs-toggle="tooltip"
   title="<?= h($title) ?>">
    <?php if (!empty($role['icon'])): ?>
        <i class="<?= h($role['icon']) ?>"></i>
    <?php endif; ?>
    <span>#<?= h($originId) ?></span>
    <?php if (!$compact && $orgName !== ''): ?>
        <span class="opacity-75 fw-normal"><?= h($orgName) ?></span>
    <?php endif; ?>
</a>
