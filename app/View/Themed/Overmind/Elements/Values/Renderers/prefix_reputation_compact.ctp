<?php
/**
 * Where this prefix sits in the ranking.
 *
 * **A position with no field size is drawn as a position and never as
 * a judgement.** 412 is excellent or unremarkable depending on how
 * many prefixes were ranked, and a widget that turned it into a word
 * would be asserting something the source did not say.
 *
 * A hijack outranks the ranking. An address inside a prefix somebody
 * else is announcing is a finding of a different kind, and it takes
 * the widget.
 *
 * @var array $data
 */
$rank = $data['headline'];
$hijack = empty($data['hijacks']) ? null : $data['hijacks'][0];
?>
<div class="vp-rw-in vp-rw-prefix">
    <?php if ($hijack !== null): ?>
        <div class="vp-rw-verdict vp-rw-v-mal"><?=
            h(__('hijacked')) ?></div>
        <?php if ($hijack['prefix'] !== null): ?>
            <div class="vp-rw-sub font-monospace"><?=
                h($hijack['prefix']) ?></div>
        <?php endif; ?>
        <?php if ($hijack['detected_asn'] !== null): ?>
            <div class="vp-rw-note font-monospace"><?= h(sprintf(
                __('announced by %s'),
                $hijack['detected_asn']
            )) ?></div>
        <?php endif; ?>
    <?php elseif ($rank !== null && $rank['position'] !== null): ?>
        <div class="vp-rw-metric">
            <span class="vp-rw-metric-n">#<?=
                h(number_format($rank['position'])) ?></span>
            <span class="vp-rw-metric-l"><?= h(__('ranked')) ?></span>
        </div>
        <?php if ($rank['at'] !== null): ?>
            <div class="vp-rw-sub"><?= h(date('Y-m-d',
                $rank['at'])) ?></div>
        <?php endif; ?>
        <?php if ($rank['family'] !== null): ?>
            <div class="vp-rw-note"><?= h($rank['family']) ?></div>
        <?php endif; ?>
    <?php else: ?>
        <div class="vp-rw-head vp-rw-quiet"><?= h(__('ranked')) ?></div>
    <?php endif; ?>
</div>
