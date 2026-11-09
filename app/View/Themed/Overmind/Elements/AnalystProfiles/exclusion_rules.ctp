<?php
/**
 * A set of rules, one per row — the exclusions, the conflict rules and
 * the signals drawn the same way: its switch, what it does and where,
 * and its settings by their names. A switch is saved when it is
 * flipped, and a setting is changed where it is read (inline_value.ctp).
 *
 * A block may head its rows by `group` (`group_looks`: icon and note),
 * split each row's settings by the map they write (`sets_by_map`), and,
 * with a value tried, say what each row contributed to it.
 *
 * @var array $block An items block
 * @var bool $editable
 * @var string|null $benchValue The value tried, when there is one
 * @var string|null $lean That value's lean, which way the contributions point
 * @var array|null $ledger Row id => contribution on that value
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');
App::uses('ValueLean', 'Tools/ValueIntelligence');

$benchValue = isset($benchValue) ? $benchValue : null;
$lean = isset($lean) ? $lean : null;
$ledger = isset($ledger) ? $ledger : array();
$looks = $block['group_looks'] ?? null;
$byMap = $block['sets_by_map'] ?? null;
$scored = $benchValue !== null && $byMap !== null;

$on = 0;
$known = 0;
$sizes = array();
foreach ($block['items'] as $item) {
    if ($looks !== null) {
        $group = (string)($item['group'] ?? '');
        $sizes[$group] = ($sizes[$group] ?? 0) + 1;
    }
    if ($item['state'] === 'missing') {
        continue;
    }
    $known++;
    $on += $item['enabled'] ? 1 : 0;
}
// A setting as a reader says it: the effective value, thousands grouped.
$reading = function (array $field) {
    if (isset($field['read_as'])) {
        return (string)$field['read_as'];
    }
    $value = $field['value'] === null ? $field['default'] : $field['value'];
    if ($value === null || $value === '') {
        return __('not set');
    }
    if (is_numeric($value) && abs($value) >= 1000) {
        return number_format((float)$value, floor($value) == $value ? 0 : 2);
    }
    return (string)$value;
};
$badgeTone = array('lean' => 't-missing', 'custom' => 't-plain', 'missing' => 't-missing');
$group = null;
?>
<?php if (!empty($block['title']) || !empty($block['blurb']) || empty($block['no_summary'])): ?>
<div class="ap-live-head">
    <div class="ap-live-head-t"><?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?></div>
    <?php if (empty($block['no_summary'])): ?>
        <div class="ap-live-tools">
            <span class="ap-rules-sum"><?= h(sprintf(__('%1$s of %2$s on'), $on, $known)) ?></span>
        </div>
    <?php endif; ?>
</div>
<?php endif; ?>
<ul class="ap-rules<?= $scored ? ' is-scored' : '' ?><?= $byMap !== null ? ' is-tuned' : '' ?>"<?=
    $scored && $lean !== null ? ' style="' . h(ValueLean::directionStyle($lean)) . '"' : '' ?>>
    <?php foreach ($block['items'] as $item): ?>
        <?php
        $switch = null;
        $settings = array();
        foreach ($item['fields'] as $field) {
            if ($field['key'] === 'enabled' && $field['type'] === 'bool') {
                $switch = $field;
            } else {
                $settings[(string)($field['map'] ?? '')][] = $field;
            }
        }
        $missing = $item['state'] === 'missing';
        $help = $item['help'] ?? null;
        $readsValue = false;
        foreach ($item['badges'] as $badge) {
            $readsValue = $readsValue || $badge['id'] === 'lean';
        }
        ?>
        <?php if ($looks !== null && (string)($item['group'] ?? '') !== $group): ?>
            <?php
            $group = (string)($item['group'] ?? '');
            $look = $looks[$group] ?? array();
            ?>
            <li class="ap-rules-grp">
                <?php if (!empty($look['icon'])): ?>
                    <i class="<?= $this->FontAwesome->getClass($look['icon']) ?>" aria-hidden="true"></i>
                <?php endif; ?>
                <span class="ap-rules-grp-t"><?= h($group === '' ? __('Ungrouped') : __($group)) ?></span>
                <span class="ap-map-grp-n"><?= h($sizes[$group]) ?></span>
                <?php if (!empty($look['note'])): ?>
                    <span class="ap-rules-grp-note"><?= h($look['note']) ?></span>
                <?php endif; ?>
            </li>
        <?php endif; ?>
        <li class="ap-rule<?= $item['enabled'] ? '' : ' is-off' ?>" data-ap-item="<?= h($item['id']) ?>"
            data-ap-state="<?= h($item['state']) ?>" data-ap-switch-scope>
            <div class="ap-rule-sw">
                <?php if ($switch !== null && $editable): ?>
                    <div class="wb-field" data-ap-unit="<?= h(implode('.', $switch['path'])) ?>">
                        <label class="visually-hidden" for="<?= h(AnalystProfileFormTool::fieldId($switch['path'])) ?>"><?=
                            h(sprintf(__('Apply %s'), $item['title'])) ?></label>
                        <?= $this->element('AnalystProfiles/field', array(
                            'field' => $switch,
                            'editable' => true,
                        )) ?>
                    </div>
                <?php elseif ($switch !== null): ?>
                    <span class="pill <?= $item['enabled'] ? 't-force' : 't-off' ?>"><?=
                        h($item['enabled'] ? __('On') : __('Off')) ?></span>
                <?php endif; ?>
            </div>
            <div class="ap-rule-body">
                <p class="ap-rule-h">
                    <span class="wb-name" title="<?= h($item['id']) ?>"><?= h($item['title']) ?></span>
                    <?php if (!empty($item['layer'])): ?>
                        <span class="ap-rule-layer"<?= empty($item['layer_title'])
                            ? '' : ' title="' . h($item['layer_title']) . '"' ?>>
                            <?php if (!empty($item['layer_icon'])): ?>
                                <i class="<?= $this->FontAwesome->getClass($item['layer_icon']) ?>" aria-hidden="true"></i>
                            <?php endif; ?>
                            <?= h($item['layer_key'] ?? __('applies to')) ?> <b><?= h($item['layer_label'] ?? $item['layer']) ?></b>
                        </span>
                    <?php endif; ?>
                    <?php foreach ($item['badges'] as $badge): ?>
                        <span class="pill <?= h($badgeTone[$badge['id']] ?? 't-missing') ?>" title="<?= h($badge['title']) ?>"><?= h($badge['label']) ?></span>
                    <?php endforeach; ?>
                    <?php if (!empty($item['trust_weighted'])): ?>
                        <span class="sig-tag is-mult" title="<?= h(__('Every point this signal contributes is'
                            . ' multiplied by how much the reporting organisation is trusted.')) ?>"><?=
                            h(__('trust weighted')) ?></span>
                    <?php endif; ?>
                </p>
                <?php if (!empty($item['description']) || $help !== null): ?>
                    <p class="ap-rule-desc">
                        <?= h((string)$item['description']) ?>
                        <?php if ($help !== null): ?>
                            <button type="button" class="sig-more" data-ap-help
                                    aria-haspopup="dialog" aria-expanded="false">
                                <i class="fa-solid fa-circle-question" aria-hidden="true"></i><?=
                                h(__('How it works')) ?>
                            </button>
                            <template class="sig-help-tpl"><?=
                                $this->element('AnalystProfiles/item_help', array('help' => $help)) ?></template>
                        <?php endif; ?>
                    </p>
                <?php endif; ?>
            </div>
            <div class="ap-rule-sets">
                <?php if (empty($settings) && !$missing): ?>
                    <span class="ap-rule-none"><?= h(__('Nothing to set')) ?></span>
                <?php endif; ?>
                <?php foreach ($settings as $map => $fields): ?>
                    <?php $mapped = $byMap !== null && isset($byMap[$map]); ?>
                    <?php if ($mapped): ?>
                        <div class="ap-rule-map">
                        <p class="ap-rule-sub"><?= h($byMap[$map]) ?></p>
                        <div class="ap-rule-map-sets">
                    <?php endif; ?>
                    <?php foreach ($fields as $field): ?>
                        <div class="ap-rule-set" data-ap-set="<?= h(implode('.', $field['path'])) ?>">
                            <label class="ap-rule-k" for="<?= h(AnalystProfileFormTool::fieldId($field['path'])) ?>"><?=
                                h($field['label']) ?></label>
                            <?php if ($editable): ?>
                                <?php // Under its map's heading the unit goes without saying: Points says points. ?>
                                <?= $this->element('AnalystProfiles/inline_value', array(
                                    'field' => $field,
                                    'unit' => $map === 'points' ? null : ($field['unit'] ?? null),
                                )) ?>
                            <?php else: ?>
                                <b class="ap-rule-v"><?= h($reading($field)) ?><?php if (!empty($field['unit'])): ?>
                                    <span class="wb-unit"><?= h($field['unit']) ?></span><?php endif; ?></b>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                    <?php if ($mapped): ?>
                        </div>
                        </div>
                    <?php endif; ?>
                <?php endforeach; ?>
            </div>
            <?php if ($scored): ?>
                <?php
                /*
                 * What the row added on the value tried. Addressed by id so
                 * the recompute can rewrite it; a row that weighs the record
                 * takes the carries/lacks ink rather than the lean's pair.
                 */
                $contribution = isset($ledger[$item['id']]) ? (int)$ledger[$item['id']] : null;
                ?>
                <div class="ap-rule-contrib<?= $readsValue ? '' : ' is-weighs' ?>"<?=
                    $missing ? '' : ' data-ap-contrib="' . h($item['id']) . '"' ?>>
                    <?php if ($missing): ?>
                        <span class="wb-sub"><?= h(__('not counted')) ?></span>
                    <?php elseif ($contribution === null): ?>
                        <div class="wb-sub"><?= h(__('did not fire')) ?></div>
                    <?php else: ?>
                        <div class="num fw-bold <?= $contribution > 0 ? 'd-up' : ($contribution < 0 ? 'd-dn' : 'd-0') ?>"><?=
                            h($contribution > 0 ? '+' . $contribution : $contribution) ?></div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </li>
    <?php endforeach; ?>
</ul>
