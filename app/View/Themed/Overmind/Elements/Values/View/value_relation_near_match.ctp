<?php
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/**
 * The Relationships rail's Near-matches: values close to this one without
 * being it, by engine. A network block that contains the address (or the
 * addresses a block contains), an ssdeep hash similar to this one, a
 * look-alike spelling of this name. Each match opens its own value page and
 * names the event it is in.
 *
 * An engine that found nothing, does not run on this type, cannot run here
 * or does not exist in MISP is one status line under the matches: a fact
 * apiece, never a block.
 *
 * Lazily loaded from ValuesController::viewRelationNearMatch.
 *
 * @var array $valueIntelligence
 */
$profile = $valueIntelligence;
$near = $profile['relationships']['near'];
$primaryType = $profile['types'][0]['type'] ?? null;
$engines = array();
foreach ($near['engines'] as $engine) {
    $engines[$engine['id']] = $engine;
}
$peeks = $near['event_peeks'] ?? array();
$fold = 6;

$permutationLabel = function ($class) {
    $labels = array(
        'omission' => __('Character dropped'),
        'repetition' => __('Character doubled'),
        'transposition' => __('Neighbours swapped'),
        'replacement' => __('Adjacent key'),
        'insertion' => __('Adjacent key inserted'),
        'vowel_swap' => __('Vowel exchanged'),
        'homoglyph' => __('Look-alike character'),
        'bitsquat' => __('One bit flipped'),
        'hyphenation' => __('Hyphen inserted'),
        'subdomain' => __('Dot inserted'),
        'addition' => __('Character appended'),
        'tld_swap' => __('Different ending'),
    );
    return $labels[$class] ?? $class;
};

$names = array(
    'cidr' => __('CIDR containment'),
    'ssdeep' => __('ssdeep similarity'),
    'typosquat' => __('Look-alike spellings'),
    'tld' => __('Domain / TLD tree'),
);
$appliesTo = array(
    'cidr' => 'ip-src / ip-dst',
    'ssdeep' => 'ssdeep',
    'typosquat' => 'domain / hostname',
);

// The matches, by engine, and a status line for every engine without one.
$sections = array();
$status = array();
foreach ($engines as $id => $engine) {
    $name = $names[$id] ?? $id;
    if ($engine['state'] === 'active' && !empty($engine['rows'])) {
        if ($id === 'cidr') {
            $title = ($engine['direction'] ?? '') === 'members'
                ? __('Addresses inside this block')
                : __('Blocks containing this address');
        } elseif ($id === 'ssdeep') {
            $title = __('Similar ssdeep hashes');
        } else {
            $title = __('Look-alike domains');
        }
        $sections[] = array('id' => $id, 'title' => $title, 'rows' => $engine['rows'], 'engine' => $engine);
        continue;
    }
    if ($engine['state'] === 'active') {
        if ($id === 'typosquat') {
            $reason = sprintf(__n('none of %s candidate spelling is here', 'none of %s candidate spellings is here',
                (int)($engine['candidates'] ?? 0)), number_format((int)($engine['candidates'] ?? 0)));
        } elseif ($id === 'ssdeep') {
            $reason = sprintf(__('nothing at %s%% or above'), (int)$near['threshold']);
        } else {
            $reason = __('nothing found');
        }
        $status[] = array('ran', $name, $reason);
    } elseif ($engine['state'] === 'unavailable') {
        $status[] = array('off', $name, __('cannot run: the extension is not loaded here'));
    } elseif ($engine['state'] === 'absent') {
        $status[] = array('none', $name, __('no such engine in MISP'));
    } else {
        $status[] = array('na', $name, sprintf(__('compares %1$s, not %2$s'), $appliesTo[$id] ?? '', (string)$primaryType));
    }
}
$statusIcons = array(
    'ran' => 'fas fa-check',
    'off' => 'fas fa-plug-circle-xmark',
    'na' => 'fas fa-minus',
    'none' => 'fas fa-minus',
);

$sub = $near['matches'] > 0
    ? h(sprintf(__n('%s near-match', '%s near-matches', $near['matches']), number_format($near['matches'])))
    : h(__('No near-match'));
$sub .= ' · <span class="vp-rel-prov"><i class="fas fa-gauge"></i>' . h(__('Machine-derived')) . '</span>';
$seen = 0;
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-near"
     style="--vp-panel-color: var(--vp-rel-near);"
     data-vp-entries
     data-vp-rel-summary="near"
     data-vp-rel-count="<?= h(number_format($near['matches'])) ?>"
     <?= empty($near['engines']) ? 'data-vp-rel-note="' . h(__('no engine applies')) . '"' : '' ?>>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Near-matches'),
        'panelIcon' => 'fas fa-code-compare',
        'panelColor' => 'var(--vp-rel-near)',
        'panelSub' => $sub,
    )) ?>

    <?php foreach ($sections as $section): ?>
        <div class="vp-nm-section">
            <div class="vp-nm-title"><?= h($section['title']) ?> <span><?= h(count($section['rows'])) ?></span></div>
            <ul class="vp-nm-list">
                <?php foreach ($section['rows'] as $row): ?>
                    <?php
                    $folded = $seen >= $fold;
                    $seen++;
                    if ($section['id'] === 'typosquat') {
                        $score = $permutationLabel($row['class'] ?? '');
                    } elseif ($row['addresses'] === null) {
                        $score = sprintf(__('%s%% similar'), (int)$row['prefix']);
                    } elseif (($section['engine']['direction'] ?? '') === 'members') {
                        $score = '';
                    } else {
                        $score = is_numeric($row['addresses'])
                            ? sprintf(__n('%s address', '%s addresses', (int)$row['addresses']), number_format((int)$row['addresses']))
                            : (string)$row['addresses'];
                    }
                    ?>
                    <li class="vp-nm-row<?= $folded ? ' d-none' : '' ?>" data-vp-entry<?= $folded ? ' data-vp-entry-fold' : '' ?>>
                        <div class="vp-nm-line">
                            <a class="vp-nm-value" href="<?= h($baseurl . '/values/view/' . ValueUrlTool::address($row['block'])) ?>"
                               title="<?= h($row['block']) ?>"><?= h($row['block']) ?></a>
                            <?php if ($score !== ''): ?>
                                <span class="vp-nm-score"><?= h($score) ?></span>
                            <?php endif; ?>
                        </div>
                        <div class="vp-nm-meta">
                            <?php if (!empty($row['object_name'])): ?>
                                <span><?= h(sprintf(__('%s object'), $row['object_name'])) ?></span>
                            <?php endif; ?>
                            <?= $this->element('Attributes/event_ref', array(
                                'event' => $peeks[(int)$row['event']] ?? array('id' => (int)$row['event']),
                            )) ?>
                            <?php if (!empty($row['org'])): ?>
                                <span class="vp-nm-org"><?= h($row['org']) ?></span>
                            <?php endif; ?>
                        </div>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endforeach; ?>
    <?= $this->element('Values/View/value_entries_more', array('count' => $seen, 'fold' => $fold)) ?>

    <?php if (empty($engines)): ?>
        <div class="vp-rail-none"><?= h(__('No engine has been asked: this value has no occurrence you can see.')) ?></div>
    <?php elseif (!empty($status)): ?>
        <ul class="vp-nm-engines">
            <?php foreach ($status as $line): ?>
                <li class="is-<?= h($line[0]) ?>">
                    <i class="<?= h($statusIcons[$line[0]]) ?>" aria-hidden="true"></i>
                    <span><strong><?= h($line[1]) ?></strong> <?= h($line[2]) ?></span>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>
