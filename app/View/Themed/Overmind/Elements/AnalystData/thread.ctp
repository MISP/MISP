<?php
/*
 * Shared Analyst Data thread renderer (Notes / Opinions / Relationships +
 * inbound relationships) for the Overmind theme.
 *
 * Rendered two ways:
 *   - viewForObject() modal fragment (AnalystData/ajax/object_thread.ctp) — pass
 *     'showModalHeader' => true to draw the modal chrome.
 *   - the full-page analystData/view page (AnalystData/view.ctp) — omit the
 *     header; the thread sits below the record's metadata card.
 *
 * Params:
 *   $analystData     — ['Note'=>[], 'Opinion'=>[], 'Relationship'=>[], 'RelationshipInbound'=>[]]
 *   $objectType      — the parent object's type (e.g. 'Note', 'Event')
 *   $objectUuid      — the parent object's uuid
 *   $showModalHeader — bool, draw the modal header strip + close button (default false)
 */
$showModalHeader = !empty($showModalHeader);

$notes         = $analystData['Note'] ?? [];
$opinions      = $analystData['Opinion'] ?? [];
$relationships = $analystData['Relationship'] ?? [];
$inbound       = $analystData['RelationshipInbound'] ?? [];
$total = count($notes) + count($opinions) + count($relationships) + count($inbound);

// Link to a referenced MISP object (analyst types open their own view).
$objLink = function ($type, $uuid) use ($baseurl) {
    if (empty($uuid)) {
        return '<span class="text-muted">&mdash;</span>';
    }
    if (in_array($type, ['Note', 'Opinion', 'Relationship'], true)) {
        $url = $baseurl . '/analystData/view/' . $type . '/' . $uuid;
    } else {
        $url = $baseurl . '/' . Inflector::tableize($type) . '/view/' . $uuid;
    }
    return sprintf(
        '<span class="badge bg-secondary-subtle text-secondary-emphasis me-1">%s</span>'
        . '<a class="text-decoration-none font-monospace small" href="%s" title="%s">%s</a>',
        h($type), h($url), h($uuid), h($uuid)
    );
};

$opinionBadge = function ($o) {
    $o = max(0, min(100, (int)$o));
    $label = $o >= 81 ? __('Strongly Agree')
        : ($o >= 61 ? __('Agree')
        : ($o >= 41 ? __('Neutral')
        : ($o >= 21 ? __('Disagree') : __('Strongly Disagree'))));
    $color = $o === 50 ? 'secondary' : ($o > 50 ? 'success' : 'danger');
    return sprintf(
        '<span class="badge bg-%s-subtle text-%s-emphasis border border-%s-subtle fw-semibold">%s &middot; %d/100</span>',
        $color, $color, $color, h($label), $o
    );
};

// Per-item controls: an "add child analyst data" dropdown targeting
// this note/opinion/relationship, plus Edit/Delete when editable.
$itemActions = function ($item, $type) use ($baseurl, $me) {
    if (empty($item['uuid'])) {
        return '';
    }
    $controls = '';

    if (!empty($me['Role']['perm_analyst_data'])) {
        $u = h($item['uuid']);
        $addItem = function ($t, $icon, $label) use ($baseurl, $u, $type) {
            return sprintf(
                '<li><a class="dropdown-item" href="#" onclick="event.preventDefault(); openModalChained(\'%s/analystData/add/%s/%s/%s\');">'
                . '<i class="%s me-2"></i>%s</a></li>',
                h($baseurl), $t, $u, h($type), $icon, h($label)
            );
        };
        $controls .=
            '<div class="dropdown">'
            . '<button class="btn btn-sm btn-light p-1" type="button" data-bs-toggle="dropdown" aria-expanded="false" title="' . h(__('Add analyst data')) . '"><i class="fas fa-plus"></i></button>'
            . '<ul class="dropdown-menu dropdown-menu-end shadow-sm">'
            . $addItem('Note', 'misp-icon misp-icon-analyst-note misp-simple', __('Add note'))
            . $addItem('Opinion', 'misp-icon misp-icon-analyst-opinion misp-simple', __('Add opinion'))
            . $addItem('Relationship', 'fas fa-diagram-project', __('Add relationship'))
            . '</ul></div>';
    }

    if (!empty($item['_canEdit']) && !empty($item['id'])) {
        $id = (int)$item['id'];
        $controls .= sprintf(
            '<a href="#" class="text-secondary" title="%s" onclick="event.preventDefault(); openModalChained(\'%s/analystData/edit/%s/%d\');"><i class="fas fa-pen-to-square"></i></a>'
            . '<a href="#" class="text-danger" title="%s" onclick="event.preventDefault(); openModalChained(\'%s/analystData/delete/%s/%d\', \'sm\');"><i class="fas fa-trash"></i></a>',
            __('Edit'), h($baseurl), h($type), $id,
            __('Delete'), h($baseurl), h($type), $id
        );
    }

    if ($controls === '') {
        return '';
    }
    return '<div class="ms-auto d-flex gap-2 flex-shrink-0 align-items-center">' . $controls . '</div>';
};

$metaLine = function ($item) {
    $bits = [];
    if (!empty($item['authors'])) {
        $bits[] = '<i class="fas fa-user me-1"></i>' . h($item['authors']);
    }
    if (!empty($item['created'])) {
        $bits[] = '<i class="fas fa-clock me-1"></i>' . h($item['created']);
    }
    return empty($bits) ? '' : '<div class="text-muted small mt-1">' . implode(' &nbsp;·&nbsp; ', $bits) . '</div>';
};

// Renders a Note/Opinion item card, then recurses into the child notes/opinions
// attached to it (analyst data on analyst data), indented under the parent.
$renderNode = function ($item, $type) use (&$renderNode, $opinionBadge, $itemActions, $metaLine) {
    ob_start();
    ?>
    <div class="border rounded p-2">
        <?php if ($type === 'Opinion'): ?>
            <div class="d-flex align-items-center gap-2">
                <?= $opinionBadge($item['opinion'] ?? 0) ?>
                <?= $itemActions($item, 'Opinion') ?>
            </div>
            <?php if (!empty($item['comment'])): ?>
                <div class="mt-1" style="white-space:pre-wrap;"><?= h($item['comment']) ?></div>
            <?php endif; ?>
        <?php else: ?>
            <div class="d-flex align-items-start gap-2">
                <div class="flex-grow-1" style="white-space:pre-wrap;"><?= h($item['note'] ?? '') ?></div>
                <?= $itemActions($item, 'Note') ?>
            </div>
        <?php endif; ?>
        <?= $metaLine($item) ?>
        <?php
        $childNotes    = $item['Note'] ?? [];
        $childOpinions = $item['Opinion'] ?? [];
        if (!empty($childNotes) || !empty($childOpinions)): ?>
            <div class="mt-2 ms-3 ps-2 border-start d-flex flex-column gap-2">
                <?php foreach ($childNotes as $cn) { echo $renderNode($cn, 'Note'); } ?>
                <?php foreach ($childOpinions as $co) { echo $renderNode($co, 'Opinion'); } ?>
            </div>
        <?php endif; ?>
    </div>
    <?php
    return ob_get_clean();
};
?>

<?php if ($showModalHeader): ?>
<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between bg-analystData bg-opacity-10"
     style="border-bottom:2px solid var(--analystData);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-analystData"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Analyst Data') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-clipboard-list text-analystData" style="font-size:1.2rem;"></i>
            <?= h($objectType) ?>
        </h4>
        <p class="text-muted mb-0 font-monospace" style="font-size:.72rem;"><?= h($objectUuid) ?></p>
    </div>
    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
</div>
<?php endif; ?>

<div class="container-fluid px-4 py-4">

    <?php if ($total === 0): ?>
        <div class="text-center text-muted py-4">
            <i class="fas fa-comment-slash mb-2" style="font-size:1.5rem;"></i>
            <div><?= __('No analyst data attached to this %s yet.', strtolower($objectType)) ?></div>
        </div>
    <?php else: ?>
    <div class="d-flex flex-column gap-4">

        <!-- ── NOTES ───────────────────────────────────────────── -->
        <?php if (!empty($notes)): ?>
            <div>
                <div class="text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                    <i class="misp-icon misp-icon-analyst-note misp-simple me-1"></i><?= __('Notes') ?> (<?= count($notes) ?>)
                </div>
                <div class="d-flex flex-column gap-2">
                    <?php foreach ($notes as $note) { echo $renderNode($note, 'Note'); } ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- ── OPINIONS ────────────────────────────────────────── -->
        <?php if (!empty($opinions)): ?>
            <div>
                <div class="text-success fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                    <i class="misp-icon misp-icon-analyst-opinion misp-simple me-1"></i><?= __('Opinions') ?> (<?= count($opinions) ?>)
                </div>
                <div class="d-flex flex-column gap-2">
                    <?php foreach ($opinions as $op) { echo $renderNode($op, 'Opinion'); } ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- ── RELATIONSHIPS (outbound) ────────────────────────── -->
        <?php if (!empty($relationships)): ?>
            <div>
                <div class="text-info fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                    <i class="fas fa-diagram-project me-1"></i><?= __('Relationships') ?> (<?= count($relationships) ?>)
                </div>
                <div class="d-flex flex-column gap-2">
                    <?php foreach ($relationships as $rel): ?>
                        <div class="border rounded p-2">
                            <div class="d-flex align-items-center gap-2 flex-wrap">
                                <?php if (!empty($rel['relationship_type'])): ?>
                                    <span class="badge bg-info-subtle text-info-emphasis border border-info-subtle">
                                        <?= h($rel['relationship_type']) ?>
                                    </span>
                                <?php endif; ?>
                                <i class="fas fa-arrow-right text-muted"></i>
                                <?= $objLink($rel['related_object_type'] ?? '', $rel['related_object_uuid'] ?? '') ?>
                                <?= $itemActions($rel, 'Relationship') ?>
                            </div>
                            <?php
                            $relNotes    = $rel['Note'] ?? [];
                            $relOpinions = $rel['Opinion'] ?? [];
                            if (!empty($relNotes) || !empty($relOpinions)): ?>
                                <div class="mt-2 ms-3 ps-2 border-start d-flex flex-column gap-2">
                                    <?php foreach ($relNotes as $cn) { echo $renderNode($cn, 'Note'); } ?>
                                    <?php foreach ($relOpinions as $co) { echo $renderNode($co, 'Opinion'); } ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- ── RELATIONSHIPS (inbound) ─────────────────────────── -->
        <?php if (!empty($inbound)): ?>
            <div>
                <div class="text-info fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
                    <i class="fas fa-diagram-project me-1"></i><?= __('Inbound relationships') ?> (<?= count($inbound) ?>)
                </div>
                <div class="d-flex flex-column gap-2">
                    <?php foreach ($inbound as $rel): ?>
                        <div class="border rounded p-2 d-flex align-items-center gap-2 flex-wrap">
                            <?= $objLink($rel['object_type'] ?? '', $rel['object_uuid'] ?? '') ?>
                            <i class="fas fa-arrow-right text-muted"></i>
                            <?php if (!empty($rel['relationship_type'])): ?>
                                <span class="badge bg-info-subtle text-info-emphasis border border-info-subtle">
                                    <?= h($rel['relationship_type']) ?>
                                </span>
                            <?php endif; ?>
                            <span class="text-muted small"><?= __('this %s', strtolower($objectType)) ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

    </div>
    <?php endif; ?>

</div>
