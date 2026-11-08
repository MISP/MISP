<?php
/**
 * The full comparison: the profile in force beside the candidate, then
 * every ledger row of the value under assessment and the values pinned.
 * It computes and writes nothing. Shared by the modal the view and the
 * editor open and by the simulate page.
 *
 * @var array $base The candidate profile
 * @var array|null $in_force
 * @var array|null $detail
 * @var string|null $focus
 * @var array $values
 * @var array $comparison
 * @var array $comparison_set
 * @var int $context_builds
 * @var array|null $dates
 * @var bool $candidate_valid
 * @var array $errors
 * @var array $warnings
 * @var array $bands
 * @var bool $modal
 */
$bench = array(
    'detail' => $detail,
    'focus' => $focus,
    'values' => $values,
    'comparison' => $comparison,
    'comparison_set' => $comparison_set,
    'context_builds' => $context_builds,
    'dates' => isset($dates) ? $dates : null,
);
?>
<div class="ap-compare">
    <div class="ap-compare-sides">
        <div class="ap-side">
            <span class="pill t-plain"><?= h(__('in force')) ?></span>
            <div class="ap-side-t">
                <b><?= h($in_force === null ? __('Nothing') : $in_force['name']) ?></b>
                <span><?= h($in_force === null
                    ? __('No profile applies to you, so this column is what no'
                        . ' scoring at all looks like.')
                    : __('The column your pages are scored by today.')) ?></span>
            </div>
        </div>
        <div class="ap-side is-candidate">
            <span class="pill t-force"><?= h(__('candidate')) ?></span>
            <div class="ap-side-t">
                <b><?= h($base['name']) ?></b>
                <span><?= h(__('Scored in memory, never written.')) ?></span>
            </div>
        </div>
    </div>

    <?php foreach ($errors as $error): ?>
        <div class="wb-note bad mb-2"><?= h($error) ?></div>
    <?php endforeach; ?>
    <?php foreach ($warnings as $warning): ?>
        <div class="wb-note warn mb-2"><?= h($warning) ?></div>
    <?php endforeach; ?>
    <?php if (!$candidate_valid): ?>
        <div class="wb-note bad mb-2">
            <b><?= h(__('This candidate could not be saved.')) ?></b>
            <?= h(__('It is simulated anyway — seeing what a document would'
                . ' do is how you find out that it is wrong.')) ?>
        </div>
    <?php endif; ?>
    <p class="ap-compare-note">
        <b class="num"><?= h($context_builds) ?></b>
        <?= h(__n('context build.', 'context builds.', $context_builds)) ?>
        <?= $context_builds <= count($values)
            ? h(__('The two profiles have the same exclusions, so both columns'
                . ' are scored over the same rows and only the weighting'
                . ' differs.'))
            : h(__('The two profiles exclude different rows, so each column is'
                . ' scored over a different set of them — the row counts'
                . ' themselves differ.')) ?>
    </p>

    <div class="wb-bench ap-compare-bench">
        <?= $this->element('AnalystProfiles/bench', array(
            'bench' => $bench,
            'bands' => $bands,
            'full' => true,
            'modal' => $modal,
            'profileId' => $base['id'],
        )) ?>
    </div>
</div>
