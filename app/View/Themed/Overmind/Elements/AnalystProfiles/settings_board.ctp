<?php
/**
 * A profile on the server settings frame: its sections on the left, the
 * one on screen on the right, each parameter editable where it is shown.
 *
 * Every section is rendered and all but one hidden, so the search reads
 * the whole document from the page. `view?fragment=board` renders this
 * alone: analyst-profile-settings.js redraws it after an inline save.
 *
 * @var array $profile
 * @var array $sections
 * @var array $groups
 * @var array $bench
 * @var string $raw
 * @var string|null $value
 * @var string|null $open_section
 * @var bool $may_edit
 * @var array|null $standing This profile's row of the index board
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');
App::uses('ProfileActionsTool', 'Tools/AnalystProfile');

$readings = AnalystProfileFormTool::benchReadings($bench['detail']);
$benched = !empty($bench['values']) ? $bench['values'][0] : null;

// Drawn under another section's entry: the rules that refuse to lean
// sit with the lean.
$joins = array('escalations' => 'thresholds');
$icons = array(
    'signals' => 'wave-square',
    'thresholds' => 'gauge',
    'escalations' => 'scale-balanced',
    'exclusions' => 'ban',
    'relevance' => 'clock-rotate-left',
    'reference' => 'shield-halved',
    'enrichment' => 'puzzle-piece',
    'context' => 'eye',
    'galaxies' => 'crosshairs',
);

$panes = array();
$grouped = array_fill_keys(array_keys($groups), array());
$fallback = array_key_last($grouped);
foreach ($sections as $id => $section) {
    if (isset($joins[$id]) && isset($sections[$joins[$id]])) {
        continue;
    }
    $key = isset($section['group']) && isset($grouped[$section['group']])
        ? $section['group']
        : $fallback;
    $grouped[$key][$id] = $section;
    $panes[$id] = array($section);
}
foreach ($joins as $id => $host) {
    if (isset($sections[$id]) && isset($panes[$host])) {
        $panes[$host][] = $sections[$id];
    }
}
$open = isset($joins[$open_section]) ? $joins[$open_section] : $open_section;
if ($open !== 'raw' && !isset($panes[$open])) {
    $open = array_key_first($panes);
}

$count = function (array $section) {
    $n = 0;
    foreach ($section['blocks'] as $block) {
        if ($block['kind'] === 'items') {
            $n += count($block['items']);
        } elseif (!empty($block['fields'])) {
            $n += count($block['fields']);
        } elseif ($block['kind'] === 'map') {
            $n += count($block['entries']);
        }
    }
    return $n;
};
// Entries this instance cannot honour: a signal it lacks, a module it has off.
$attention = function (array $section) {
    $n = 0;
    foreach ($section['blocks'] as $block) {
        if ($block['kind'] === 'items') {
            foreach ($block['items'] as $item) {
                $n += ($item['state'] ?? '') === 'missing' ? 1 : 0;
            }
        } elseif ($block['kind'] === 'map') {
            foreach ($block['entries'] as $entry) {
                $n += empty($entry['missing']) ? 0 : 1;
            }
        }
    }
    return $n;
};

$fork = null;
if (!$may_edit && $standing !== null) {
    $writes = ProfileActionsTool::writes($standing, array());
    $fork = empty($writes['fork']) ? null : $writes['fork'][0];
}
?>
<div class="ss-layout">
    <div class="ss-layout-nav">
        <div class="ss-nav-sticky">
            <nav class="card shadow-sm ss-nav" aria-label="<?= h(__('Sections')) ?>">
                <div class="card-body p-2">
                    <button type="button" class="ss-nav-search" data-ap-search-open>
                        <i class="fas fa-magnifying-glass"></i>
                        <span><?= h(__('Search parameters')) ?></span>
                        <kbd>Ctrl K</kbd>
                    </button>
                    <?php foreach ($groups as $key => $label): ?>
                        <?php if (empty($grouped[$key])) { continue; } ?>
                        <hr class="my-2">
                        <div class="ss-nav-group">
                            <div class="ss-eyebrow px-2 pt-2 pb-1"><?= h($label) ?></div>
                            <?php foreach ($grouped[$key] as $id => $section): ?>
                                <?php
                                $tally = 0;
                                $warn = 0;
                                foreach ($panes[$id] as $member) {
                                    $tally += $count($member);
                                    $warn += $attention($member);
                                }
                                ?>
                                <a class="ss-nav-item<?= $open === $id ? ' active' : '' ?>"
                                   href="?section=<?= h($id) ?>" data-ap-nav="<?= h($id) ?>">
                                    <i class="fas fa-<?= h($icons[$id] ?? 'sliders') ?> fa-fw"></i>
                                    <span class="ss-nav-label"><?= h($section['title']) ?></span>
                                    <?php if ($warn > 0): ?>
                                        <span class="ss-nav-badge ss-nav-badge-warning"
                                              title="<?= h(__('Entries this instance cannot honour')) ?>"><?=
                                            h($warn) ?></span>
                                    <?php else: ?>
                                        <span class="ss-nav-badge ss-nav-badge-neutral"><?= h($tally) ?></span>
                                    <?php endif; ?>
                                </a>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                    <hr class="my-2">
                    <div class="ss-eyebrow px-2 pt-2 pb-1"><?= h(__('The document')) ?></div>
                    <a class="ss-nav-item<?= $open === 'raw' ? ' active' : '' ?>"
                       href="?section=raw" data-ap-nav="raw">
                        <i class="fas fa-code fa-fw"></i>
                        <span class="ss-nav-label"><?= h(__('Raw JSON')) ?></span>
                        <span class="ss-nav-badge ss-nav-badge-neutral"><?=
                            h(sprintf('%.1f KB', strlen($raw) / 1024)) ?></span>
                    </a>
                </div>
            </nav>
        </div>
    </div>
    <div class="ss-layout-main">
        <?php if (!empty($loader_errors)): ?>
            <?= $this->element('AnalystProfiles/loader_errors', array(
                'loader_errors' => $loader_errors,
            )) ?>
        <?php endif; ?>
        <?php foreach ($errors as $error): ?>
            <div class="wb-note bad mb-2"><?= h($error) ?></div>
        <?php endforeach; ?>
        <?php foreach ($warnings as $warning): ?>
            <div class="wb-note warn mb-2"><?= h($warning) ?></div>
        <?php endforeach; ?>
        <?php foreach ($legacy as $note): ?>
            <div class="wb-note mb-2">
                <b><?= h(__('Written by an older version.')) ?></b>
                <?= h($note) ?>
            </div>
        <?php endforeach; ?>

        <?php if (!$may_edit): ?>
            <div class="ap-readonly">
                <i class="fas fa-lock" aria-hidden="true"></i>
                <span><?= h(__('This profile is not yours, so it is read-only'
                    . ' here. Fork it and the copy opens ready to edit.')) ?></span>
                <?php if ($fork !== null): ?>
                    <?php $forkUrl = $this->Html->url($fork['url']); ?>
                    <a class="btn btn-sm btn-primary" href="<?= h($forkUrl) ?>"
                       onclick="event.preventDefault(); openModal(<?= h(json_encode($forkUrl)) ?>, 'md');">
                        <i class="fas fa-code-branch me-1" aria-hidden="true"></i><?= h($fork['label']) ?>
                    </a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?= $this->element('AnalystProfiles/value_bar', array(
            'benched' => $benched,
            'open' => $open,
        )) ?>

        <?php foreach ($panes as $id => $members): ?>
            <div class="ap-pane" data-ap-pane="<?= h($id) ?>"<?= $open === $id ? '' : ' hidden' ?>>
                <?php foreach ($members as $section): ?>
                    <?= $this->element('AnalystProfiles/section', array(
                        'section' => $section,
                        'editable' => false,
                        'open' => true,
                        'ledger' => $readings['ledger'],
                        'benchValue' => $benched,
                        'marks' => $readings['marks'],
                        'runway' => $readings['runway'],
                        'lean' => $readings['lean'],
                        'compact' => true,
                        'mayEdit' => $may_edit,
                        'axes' => $benched !== null && $bench['detail'] !== null
                            ? $bench['detail']['axes'] : null,
                    )) ?>
                <?php endforeach; ?>
            </div>
        <?php endforeach; ?>
        <?= $this->element('AnalystProfiles/raw_pane', array('open' => $open === 'raw')) ?>
    </div>
</div>
<?php if ($may_edit): ?>
    <?= $this->Form->create('AnalystProfile', array(
        'id' => 'ap-token',
        'url' => $this->Html->url(array('action' => 'edit', $profile['id'])),
        'style' => 'display:none',
    )) ?>
    <?= $this->Form->end() ?>
<?php endif; ?>
