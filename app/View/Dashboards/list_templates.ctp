<?php
/**
 * Dashboard template gallery (PRD §5.4, Phase 4 task 1).
 *
 * Renders inside Layouts/dashboard.ctp (DD-08). Server-rendered
 * gallery grouped by ownership — My templates / Featured / Shared
 * with me. Sections render only when non-empty.
 *
 * Reuses the .misp-gallery-* CSS shell from the widget-gallery
 * scaffolding (Elements/dashboard/gallery/grid.ctp). Cards layer
 * template-specific markup on top via .misp-template-card-* hooks
 * so the existing widget-gallery styles stay untouched.
 *
 * Hover-reveal toolbar (per user direction): three small icon
 * buttons (Use this / Edit / Delete) appear in the top-right of
 * each card on :hover and :focus-within. Keyboard-reachable via
 * Tab from the card body.
 *
 * Data contract (set by DashboardsController::listTemplates):
 *   - mineTemplates / featuredTemplates / sharedTemplates: arrays
 *     of CakePHP find() rows (Dashboard + User containment)
 *   - currentUserId (int), isSiteAdmin (bool)
 *   - orgMap / roleMap / permFlagLabels: lookup arrays for badges
 *
 * Search filter wired client-side by template-gallery.module.mjs
 * (matches on name + description + uuid via the data-template-
 * search-text attribute the view inlines per card).
 */
$baseurl = Configure::read('MISP.baseurl') ?: '';

/**
 * Render one card. Inline closure so the per-section loops below
 * stay readable. The HTML is mostly delegated to .misp-gallery-card
 * + .misp-template-card-* styles; per-card data attributes carry
 * the search/filter inputs.
 */
$renderCard = function (
    array $row,
    string $ownership
) use ($currentUserId, $isSiteAdmin, $orgMap, $roleMap, $permFlagLabels, $baseurl) {
    $dash = $row['Dashboard'];
    $user = isset($row['User']) ? $row['User'] : array();
    $uuid = $dash['uuid'];
    $name = $dash['name'];
    $description = !empty($dash['description']) ? $dash['description'] : '';
    $ownerEmail = !empty($user['email']) ? $user['email'] : '';
    $isOwn = ((int)$dash['user_id'] === (int)$currentUserId);
    $canEdit = $isSiteAdmin || $isOwn;

    // Widgets used: allow/deny split provided by the controller's
    // afterFind. Total count is allow+deny.
    $allow = isset($dash['widgets']['allow']) ? $dash['widgets']['allow'] : array();
    $deny  = isset($dash['widgets']['deny'])  ? $dash['widgets']['deny']  : array();
    $widgetCount = count($allow) + count($deny);

    // Build the search-text payload up front so the JS doesn't have
    // to walk per-card DOM nodes on every keystroke.
    $searchText = strtolower(implode(' ', array_filter(array(
        $name,
        $description,
        $uuid,
        $ownerEmail,
    ))));

    // Restrict-to badges. Site admins set these on save; the
    // listTemplates query already filters out templates the user
    // can't see, so any badge here is a fact (not a permission gate).
    $restrictBadges = array();
    if (!empty($dash['restrict_to_org_id'])) {
        $orgName = isset($orgMap[$dash['restrict_to_org_id']])
            ? $orgMap[$dash['restrict_to_org_id']]
            : sprintf('#%d', $dash['restrict_to_org_id']);
        $restrictBadges[] = sprintf(__('Org: %s'), $orgName);
    }
    if (!empty($dash['restrict_to_role_id'])) {
        $roleName = isset($roleMap[$dash['restrict_to_role_id']])
            ? $roleMap[$dash['restrict_to_role_id']]
            : sprintf('#%d', $dash['restrict_to_role_id']);
        $restrictBadges[] = sprintf(__('Role: %s'), $roleName);
    }
    if (!empty($dash['restrict_to_permission_flag'])) {
        $flag = $dash['restrict_to_permission_flag'];
        $flagLabel = isset($permFlagLabels[$flag]) ? $permFlagLabels[$flag] : $flag;
        $restrictBadges[] = sprintf(__('Permission: %s'), $flagLabel);
    }
?>
<article class="misp-gallery-card misp-template-card"
         data-misp-template-card
         data-template-uuid="<?= h($uuid) ?>"
         data-template-ownership="<?= h($ownership) ?>"
         data-template-search-text="<?= h($searchText) ?>">
    <span class="misp-gallery-card-thumbnail misp-template-card-thumbnail"
          aria-hidden="true">
        <!-- Thumbnail miniature: pending Phase 4 task 2 (server-
             rendered preview of the template's layout, cached on
             disk). Today shows a generic placeholder glyph so the
             card has visual weight; the actual miniature lands in a
             subsequent commit. -->
        <svg viewBox="0 0 80 45" preserveAspectRatio="xMidYMid meet"
             width="100%" height="100%" fill="none"
             stroke="currentColor" stroke-width="1.5"
             stroke-linecap="round" stroke-linejoin="round">
            <rect x="6"  y="6"  width="30" height="14" rx="2" />
            <rect x="40" y="6"  width="34" height="14" rx="2" />
            <rect x="6"  y="24" width="20" height="15" rx="2" />
            <rect x="30" y="24" width="20" height="15" rx="2" />
            <rect x="54" y="24" width="20" height="15" rx="2" />
        </svg>
    </span>
    <span class="misp-gallery-card-body misp-template-card-body">
        <span class="misp-gallery-card-title misp-template-card-title"
              data-misp-template-card-title><?= h($name) ?></span>
        <?php if ($description !== ''): ?>
            <span class="misp-gallery-card-description misp-template-card-description"
                  data-misp-template-card-description><?= h($description) ?></span>
        <?php endif; ?>
        <span class="misp-template-card-meta">
            <?php if (!empty($dash['default'])): ?>
                <span class="misp-template-badge misp-template-badge-default"
                      title="<?= __('Marked as the global default template') ?>">
                    <?= __('Default') ?>
                </span>
            <?php endif; ?>
            <?php if (!empty($dash['selectable']) && empty($dash['default'])): ?>
                <span class="misp-template-badge misp-template-badge-selectable"
                      title="<?= __('Selectable by other users') ?>">
                    <?= __('Selectable') ?>
                </span>
            <?php endif; ?>
            <?php if ($isOwn): ?>
                <span class="misp-template-badge misp-template-badge-mine"
                      title="<?= __('You own this template') ?>">
                    <?= __('Mine') ?>
                </span>
            <?php endif; ?>
            <?php foreach ($restrictBadges as $badgeText): ?>
                <span class="misp-template-badge misp-template-badge-restrict"
                      title="<?= __('Visibility restriction') ?>"><?= h($badgeText) ?></span>
            <?php endforeach; ?>
            <span class="misp-template-card-widgetcount"
                  title="<?= sprintf(__('%d widget(s) in this template'), $widgetCount) ?>">
                <?= sprintf(__n('%d widget', '%d widgets', $widgetCount), $widgetCount) ?>
            </span>
            <?php if (!$isOwn && $ownerEmail !== ''): ?>
                <span class="misp-template-card-owner"
                      title="<?= __('Owner') ?>"><?= h($ownerEmail) ?></span>
            <?php endif; ?>
        </span>
    </span>
    <span class="misp-template-card-actions" data-misp-template-card-actions>
        <?php /* "Use this template" placeholder — links to the same URL
              the v1 carryover view used. The Reset-from-template flow
              (Phase 4 task 6) replaces this with a proper handler +
              confirmation prompt; the index() action ignores the UUID
              arg today (v2 quirk carried from Phase 1). */ ?>
        <a href="<?= h($baseurl) ?>/dashboards/index/<?= h($uuid) ?>"
           class="misp-template-card-action"
           data-misp-template-action="use"
           title="<?= __('Load this template as your dashboard') ?>"
           aria-label="<?= __('Load this template as your dashboard') ?>">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                 stroke="currentColor" stroke-width="1.5"
                 stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M4 3 L12 8 L4 13 Z" />
            </svg>
        </a>
        <?php if ($canEdit): ?>
            <a href="<?= h($baseurl) ?>/dashboards/saveTemplate/<?= h($uuid) ?>"
               class="misp-template-card-action"
               data-misp-template-action="edit"
               title="<?= __('Edit template metadata') ?>"
               aria-label="<?= __('Edit template metadata') ?>">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                     stroke="currentColor" stroke-width="1.5"
                     stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M10.5 2.5 L13.5 5.5 L5 14 L2 14 L2 11 Z" />
                    <line x1="9" y1="4" x2="12" y2="7" />
                </svg>
            </a>
            <?php
                $trashSvg = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" '
                    . 'stroke="currentColor" stroke-width="1.5" '
                    . 'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
                    . '<path d="M2.5 4 L13.5 4" />'
                    . '<path d="M6 4 L6 2.5 L10 2.5 L10 4" />'
                    . '<path d="M3.5 4 L4.5 13.5 L11.5 13.5 L12.5 4" />'
                    . '<line x1="6.5" y1="7" x2="6.5" y2="11" />'
                    . '<line x1="9.5" y1="7" x2="9.5" y2="11" />'
                    . '</svg>';
                echo $this->Form->postLink($trashSvg, array(
                    'controller' => 'dashboards',
                    'action' => 'deleteTemplate',
                    $uuid,
                ), array(
                    'class' => 'misp-template-card-action misp-template-card-action-danger',
                    'data-misp-template-action' => 'delete',
                    'title' => __('Delete this template'),
                    'aria-label' => __('Delete this template'),
                    'escape' => false,
                ), __('Are you sure you want to delete the template "%s"?', $name));
            ?>
        <?php endif; ?>
    </span>
</article>
<?php
};
?>
<header class="misp-dashboard-header misp-template-gallery-header">
    <div class="misp-template-gallery-title-block">
        <h1 class="misp-dashboard-title"><?= __('Dashboard templates') ?></h1>
        <p class="misp-template-gallery-subtitle"><?= __('Templates are pre-built dashboard layouts. Use one as your starting point, or save your current dashboard to share with others.') ?></p>
    </div>
    <div class="misp-dashboard-modecontrols">
        <a href="<?= h($baseurl) ?>/dashboards"
           class="misp-dashboard-btn"
           data-misp-template-gallery-action="back"
           title="<?= __('Return to your dashboard') ?>">
            <?= __('← Back to dashboard') ?>
        </a>
        <a href="<?= h($baseurl) ?>/dashboards/saveTemplate"
           class="misp-dashboard-btn misp-dashboard-btn-primary"
           data-misp-template-gallery-action="save-current"
           title="<?= __('Save the current dashboard as a new template') ?>">
            <?= __('Save current dashboard as template') ?>
        </a>
    </div>
</header>

<main class="misp-dashboard-page-main misp-template-gallery-page">
    <div class="misp-gallery misp-template-gallery"
         data-misp-template-gallery-root>
        <header class="misp-gallery-header">
            <label class="misp-gallery-search-label">
                <span class="visually-hidden"><?= __('Search templates') ?></span>
                <input type="search"
                       class="misp-gallery-search"
                       data-misp-template-gallery-search
                       placeholder="<?= __('Search templates…') ?>"
                       autocomplete="off"
                       spellcheck="false" />
            </label>
            <span class="misp-gallery-counter"
                  data-misp-template-gallery-counter
                  aria-live="polite"></span>
        </header>

        <div class="misp-gallery-body" data-misp-template-gallery-body>
            <?php if (!empty($mineTemplates)): ?>
                <section class="misp-gallery-category misp-template-gallery-section"
                         data-misp-template-gallery-section="mine">
                    <h2 class="misp-gallery-category-heading"><?= __('My templates') ?></h2>
                    <div class="misp-gallery-category-grid">
                        <?php foreach ($mineTemplates as $row) $renderCard($row, 'mine'); ?>
                    </div>
                </section>
            <?php endif; ?>

            <?php if (!empty($featuredTemplates)): ?>
                <section class="misp-gallery-category misp-template-gallery-section"
                         data-misp-template-gallery-section="featured">
                    <h2 class="misp-gallery-category-heading"><?= __('Featured') ?></h2>
                    <div class="misp-gallery-category-grid">
                        <?php foreach ($featuredTemplates as $row) $renderCard($row, 'featured'); ?>
                    </div>
                </section>
            <?php endif; ?>

            <?php if (!empty($sharedTemplates)): ?>
                <section class="misp-gallery-category misp-template-gallery-section"
                         data-misp-template-gallery-section="shared">
                    <h2 class="misp-gallery-category-heading"><?= __('Shared with me') ?></h2>
                    <div class="misp-gallery-category-grid">
                        <?php foreach ($sharedTemplates as $row) $renderCard($row, 'shared'); ?>
                    </div>
                </section>
            <?php endif; ?>

            <?php if (empty($mineTemplates) && empty($featuredTemplates) && empty($sharedTemplates)): ?>
                <p class="misp-template-gallery-empty-state">
                    <?= __('No dashboard templates are available yet. Save your current dashboard as a template to get started.') ?>
                </p>
            <?php endif; ?>
        </div>

        <p class="misp-gallery-empty misp-template-gallery-empty"
           data-misp-template-gallery-empty
           hidden><?= __('No templates match your search.') ?></p>
    </div>
</main>

<script type="module"
        src="<?= h($baseurl) ?>/js/dashboard/template-gallery.module.mjs"></script>
