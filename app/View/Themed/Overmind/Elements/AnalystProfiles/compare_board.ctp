<?php
/**
 * The full comparison: the profile in force beside the candidate, then
 * the value under assessment read by both, row by row, and the values
 * pinned. In force is grey and the candidate the primary colour all the
 * way down, so a number says whose it is before it is read. It computes
 * and writes nothing. Shared by the view's modal and the simulate page.
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
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

$bench = array(
    'detail' => $detail,
    'focus' => $focus,
    'values' => $values,
    'comparison' => $comparison,
    'comparison_set' => $comparison_set,
    'context_builds' => $context_builds,
    'dates' => isset($dates) ? $dates : null,
);
$benched = !empty($values) ? $values[0] : null;
$isPinned = $benched !== null && in_array($benched, $comparison_set, true);
?>
<div class="ap-compare">
    <div class="ap-cmp-value">
        <div class="ap-cmp-value-main">
            <span class="ap-cmp-value-k"><?= h(__('Value under assessment')) ?></span>
            <?php if ($benched !== null): ?>
                <span class="ap-cmp-value-v"><?= h($benched) ?></span>
                <span class="pill t-plain"><?= h($isPinned ? __('pinned') : __('not pinned')) ?></span>
                <?php if (!$modal): ?>
                    <?= $this->Form->postLink($isPinned ? __('Unpin') : __('Pin'),
                        array('action' => $isPinned ? 'unpin' : 'pin', ValueUrlTool::encode($benched)),
                        array('class' => 'btn btn-sm btn-outline-primary py-0 px-2')) ?>
                <?php endif; ?>
            <?php else: ?>
                <span class="ap-cmp-value-none"><?= h(__('none chosen')) ?></span>
            <?php endif; ?>
        </div>
        <?php if (!$modal): ?>
            <div class="bench-pick">
                <div class="input-group input-group-sm">
                    <input type="text" class="form-control form-control-sm"
                           data-ap-bench-input autocomplete="off" spellcheck="false"
                           placeholder="<?= h(__('try a value — an IP, a domain, a hash')) ?>">
                    <button type="button" class="btn btn-sm btn-outline-primary"
                            data-ap-bench=""><?= h(__('Try it')) ?></button>
                </div>
                <?php if (!empty($values)): ?>
                    <div class="bench-quick">
                        <span class="wb-sub"><?= h(__('yours:')) ?></span>
                        <?php foreach ($values as $candidate): ?>
                            <button type="button" class="chip <?= $candidate === $benched ? 'is-on' : '' ?>"
                                    data-ap-bench="<?= h($candidate) ?>"><?= h($candidate) ?></button>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="ap-compare-sides">
        <div class="ap-side is-was">
            <span class="ap-key is-was"><span class="ap-key-dot" aria-hidden="true"></span><?=
                h(__('in force')) ?></span>
            <div class="ap-side-t">
                <b><?= h($in_force === null ? __('Nothing') : $in_force['name']) ?></b>
                <span><?= h($in_force === null
                    ? __('No profile applies to you, so this column is what no'
                        . ' scoring at all looks like.')
                    : __('The column your pages are scored by today.')) ?></span>
            </div>
        </div>
        <span class="ap-compare-vs" aria-hidden="true"><?= h(__('vs')) ?></span>
        <div class="ap-side is-now">
            <span class="ap-key is-now"><span class="ap-key-dot" aria-hidden="true"></span><?=
                h(__('candidate')) ?></span>
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

    <div class="wb-bench ap-compare-bench">
        <?= $this->element('AnalystProfiles/bench', array(
            'bench' => $bench,
            'bands' => $bands,
            'full' => true,
            'modal' => $modal,
            'profileId' => $base['id'],
        )) ?>
    </div>
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
</div>
