<?php
/*
 * The distribution picker: the section label, a card per distribution level,
 * and the sharing-group select that only applies to level 4 — the whole field
 * group, so a form asks for distribution in one line.
 *
 * Everything is optional: the defaults read the variables the controllers
 * already set ($distributionLevels / $initialDistribution / $sharingGroups, or
 * the $distributionData bundle that Attribute::fetchDistributionData() returns),
 * so `$this->element('genericElementsBS5/Forms/distribution_field')` is enough
 * in most forms.
 *
 * Optional params:
 *   $field         string  form field (default 'distribution'); prefix it for
 *                          another model, as 'Object.distribution'
 *   $levels        array   level => label, as narrow as the form allows — a
 *                          controller drops level 4 when the user has no
 *                          sharing group, and only attributes and objects offer
 *                          level 5
 *   $value         mixed   the selected level
 *   $accent        string  accent key, see ModalAccent (default 'primary')
 *   $label         string  section label (default 'Distribution'; '' drops it)
 *   $required      bool    REQUIRED badge on the section label
 *   $hint          string  muted line under the cards
 *   $id            string  id of the hidden select; Cake's own when omitted
 *   $selectAttrs   array   extra attributes for that select — the class or the
 *                          data-* hook a host form's JS listens on
 *   $columns       int     cards per row from lg up (default: one per level)
 *   $compact       bool    draw the levels as one <select> carrying the picked
 *                          level's glyph instead of a row of cards — for a form
 *                          where distribution is a detail beside the field that
 *                          matters (an attribute's value) rather than a choice
 *                          the reader is there to make. The sharing group still
 *                          appears under it. $columns is then meaningless.
 *   $class         string  extra classes on the wrapper
 *
 * The sharing-group half:
 *   $showSg        bool    default: there is a level 4 and a list to pick from
 *   $sharingGroups array   id => name
 *   $sgField       string  default: `sharing_group_id` beside $field
 *   $sgId          string  id of the sharing-group select
 *   $sgLabel       string  its section label (default 'Sharing Group')
 *   $sgHint        string  muted line under it
 *   $sgEmpty       mixed   placeholder option (default false — no placeholder,
 *                          so the first sharing group is preselected and a
 *                          level-4 form cannot post an empty one; pass a string
 *                          where the form validates it and would rather ask)
 *
 * The levels' glyphs, tints and one-line glosses come from
 * app/Lib/Tools/DistributionLevel.php — never restate one here.
 */

$distributionData = $distributionData ?? null;

$field = $field ?? 'distribution';

$levels = $levels
    ?? $distributionLevels
    ?? ($distributionData['levels'] ?? null)
    ?? array_map(function ($meta) {
        return $meta['label'];
    }, $this->DistributionLevel->all());

if (!isset($value)) {
    $value = $initialDistribution
        ?? ($distributionData['initial'] ?? null)
        ?? key($levels);
}

$accent = $accent ?? 'primary';
$levelMeta = $this->DistributionLevel->all();

$options = [];
foreach ($levels as $level => $levelLabel) {
    $meta = $levelMeta[(int)$level] ?? $this->DistributionLevel->fallback();
    $options[] = [
        'value' => $level,
        'title' => $levelLabel,
        'sub' => $meta['sub'],
        'icon' => $meta['icon'],
        'tone' => $meta['color'],
        'toneBg' => $meta['bg'],
    ];
}

$sharingGroups = $sharingGroups
    ?? ($distributionData['sgs'] ?? null)
    ?? [];
$showSg = $showSg ?? (isset($levels[4]) && !empty($sharingGroups));


if (!isset($sgField)) {
    $dot = strrpos($field, '.');
    $sgField = $dot === false
        ? 'sharing_group_id'
        : substr($field, 0, $dot + 1) . 'sharing_group_id';
}

/* The reveal needs a selector, and the wrapper is what gets hidden — so it
 * carries an id of its own, derived from the field to stay unique in a form
 * that asks for distribution more than once. */
$sgWrapperId = 'dist-sg-' . preg_replace('/[^A-Za-z0-9]+/', '-', $field);
?>


<div class="<?= h(trim('dist-field ' . ($class ?? ''))) ?>">

    <?php if (($label ?? __('Distribution')) !== ''): ?>
        <?= $this->element('genericElementsBS5/Forms/section_label', [
            'accent' => $accent,
            'label' => $label ?? __('Distribution'),
            'required' => !empty($required),
        ]) ?>
    <?php endif; ?>

    <?php
    $shared = [
        'field' => $field,
        'options' => $options,
        'value' => $value,
        'accent' => $accent,
        'id' => $id ?? null,
        'selectAttrs' => $selectAttrs ?? [],
        'ariaLabel' => __('Distribution'),
        'reveal' => $showSg
            ? ['value' => 4, 'target' => '#' . $sgWrapperId]
            : null,
    ];
    echo empty($compact)
        ? $this->element(
            'genericElementsBS5/Forms/choice_cards',
            $shared + ['columns' => $columns ?? null]
        )
        : $this->element('genericElementsBS5/Forms/choice_select', $shared);
    ?>

    <?php if (!empty($hint)): ?>
        <?= $this->element('genericElementsBS5/Forms/field_hint', [
            'text' => $hint,
            'class' => 'mt-2',
        ]) ?>
    <?php endif; ?>

    <?php if ($showSg): ?>
        <div class="mt-3<?= (int)$value === 4 ? '' : ' d-none' ?>"
             id="<?= h($sgWrapperId) ?>">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => $accent,
                'label' => $sgLabel ?? __('Sharing Group'),
            ]) ?>
            <?= $this->Form->select($sgField, $sharingGroups, [
                'class' => 'form-select tom-select',
                'empty' => $sgEmpty ?? false,
                'data-placeholder' => is_string($sgEmpty ?? false)
                    ? $sgEmpty
                    : __('Select a sharing group…'),
            ] + (empty($sgId) ? [] : ['id' => $sgId])) ?>
            <?php if (!empty($sgHint)): ?>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => $sgHint,
                ]) ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
