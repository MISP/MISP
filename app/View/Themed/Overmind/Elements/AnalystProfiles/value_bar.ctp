<?php
/**
 * The value under assessment, above the sections: the box that picks it
 * and the three readings this profile gives it. The contributions, the
 * band marks and the lifetime curve in the sections read the same value;
 * every row of the comparison is one click away, in its modal.
 *
 * Trying a value is a GET of this page with `?value=`, so the readings
 * always describe the saved profile.
 *
 * @var array $profile
 * @var array $bench
 * @var string|null $benched The value the readings are for
 * @var string $open The section on screen, kept across the reload
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

$detail = $bench['detail'];
$pinned = $bench['comparison_set'];
$axes = $benched !== null && $detail !== null ? $detail['axes'] : null;
$here = $this->Html->url(array('action' => 'view', $profile['id']));
?>
<div class="card ap-vbar">
    <div class="ap-vbar-side">
    <form class="ap-vbar-form" method="get" action="<?= h($here) ?>">
        <input type="hidden" name="section" value="<?= h($open) ?>" data-ap-vbar-section>
        <label class="ifp-query ap-vbar-q">
            <i class="fas fa-flask ifp-q-icon" aria-hidden="true"></i>
            <input type="search" name="value" value="<?= h((string)$benched) ?>"
                   list="ap-vbar-pinned" autocomplete="off" spellcheck="false"
                   aria-label="<?= h(__('Value under assessment')) ?>"
                   placeholder="<?= h(__('Try it on a value: an IP, a domain, a hash')) ?>">
        </label>
        <?php if (!empty($pinned)): ?>
            <datalist id="ap-vbar-pinned">
                <?php foreach ($pinned as $candidate): ?>
                    <option value="<?= h($candidate) ?>"></option>
                <?php endforeach; ?>
            </datalist>
        <?php endif; ?>
        <button type="submit" class="btn btn-sm btn-outline-primary"><?= h(__('Try it')) ?></button>
    </form>
    <?php if ($axes !== null): ?>
        <?php
        // What to do with the value tried, under the box that picked it.
        $isPinned = in_array($benched, $pinned, true);
        ?>
        <div class="ap-vbar-acts">
            <a class="ap-vbar-act" data-ap-compare href="<?= h($this->Html->url(array(
                'action' => 'simulate', $profile['id'], '?' => array('value' => $benched)))) ?>"
               title="<?= h(__('This value under the profile in force and under this one, row by row.')) ?>">
                <i class="fas fa-code-compare" aria-hidden="true"></i><?= h(__('Compare this value with the current profile')) ?>
            </a>
            <?= $this->Form->postLink(
                '<i class="fas fa-thumbtack" aria-hidden="true"></i>'
                    . ($isPinned
                        ? h(__('Pinned')) . ' <b class="ap-vbar-v">' . h($benched) . '</b>'
                        : h(__('Pin'))),
                array('action' => $isPinned ? 'unpin' : 'pin', ValueUrlTool::encode($benched)),
                array(
                    'class' => 'ap-vbar-act' . ($isPinned ? ' is-pinned' : ''),
                    'escape' => false,
                    'title' => $isPinned
                        ? sprintf(__('%s is pinned: tried on every profile you open. Click to unpin it.'), $benched)
                        : __('A pinned value is tried on every profile you open.'),
                )
            ) ?>
        </div>
    <?php endif; ?>
    </div>
    <?php if ($axes !== null): ?>
        <?php
        $verdict = $bench['verdict'] ?? null;
        $asserted = $verdict !== null && ($verdict['lean'] ?? 'none') !== 'none';
        ?>
        <div class="ap-vbar-read">
            <?php if ($verdict !== null && !$asserted): ?>
                <?php
                // Nothing to read: said once, with what each axis is missing.
                $tooCommon = ($verdict['relevance']['reason'] ?? null) === 'rows_not_read';
                ?>
                <div class="ap-vbar-none">
                    <span class="ap-vbar-none-ico" aria-hidden="true"><i class="fas fa-magnifying-glass"></i></span>
                    <div class="ap-vbar-none-t">
                        <b><?= h(sprintf(__('Nothing asserted about %s'), $benched)) ?></b>
                        <span class="ap-vbar-none-facts">
                            <span title="<?= h(__('No organisation called it a threat or harmless.')) ?>"><i class="ap-axis-split" aria-hidden="true"></i><?= h(__('No votes')) ?></span>
                            <span title="<?= h(__('No signal fired, so there is no signal strength.')) ?>"><i class="fas fa-signal" aria-hidden="true"></i><?= h(__('Not scored')) ?></span>
                            <span title="<?= h($tooCommon
                                ? __('Too common for MISP to read its rows, so no clock runs.')
                                : __('Nothing is recorded, so no clock runs.')) ?>"><i class="fas fa-hourglass-half" aria-hidden="true"></i><?= h($tooCommon
                                ? __('Too common to read')
                                : __('Nothing recorded')) ?></span>
                        </span>
                    </div>
                </div>
            <?php elseif ($verdict !== null): ?>
                <?php // The value page's own three axes, drawn small: the same element, the same reading. ?>
                <div class="ap-vbar-axes">
                    <?= $this->element('Values/View/value_verdict_axes', array('verdict' => $bench['verdict'])) ?>
                </div>
            <?php else: ?>
            <span class="ap-vbar-ax">
                <span class="k"><?= h(__('lean')) ?></span>
                <b><?= h($axes['lean']['after'] === null ? __('none') : $axes['lean']['after']) ?></b>
            </span>
            <span class="ap-vbar-ax">
                <span class="k"><?= h(__('signal strength')) ?></span>
                <b class="num"><?= h($axes['signal_strength']['after']) ?></b>
                <span class="pill t-plain"><?= h($axes['band']['after']) ?></span>
            </span>
            <span class="ap-vbar-ax">
                <span class="k"><?= h(__('relevance')) ?></span>
                <b><?= h($axes['relevance']['after'] === null
                    ? __('no clock')
                    : (($axes['relevance']['label'] ?? '') !== ''
                        ? $axes['relevance']['label']
                        : $axes['relevance']['after'])) ?></b>
            </span>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
