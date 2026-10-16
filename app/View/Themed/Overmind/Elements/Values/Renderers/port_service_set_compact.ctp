<?php
/**
 * How much is exposed, and which of it matters.
 *
 * The count is the size of the answer; the notable ports are the part
 * a reader reacts to. Where nothing notable is open the count stands
 * alone with the lowest few port numbers under it, because *80 and 443
 * and nothing else* is itself an answer and an empty second line would
 * read as a rendering that failed.
 *
 * @var array $data
 */
$notable = $data['notable'];
$shown = empty($notable)
    ? array_slice($data['services'], 0, 4)
    : array_slice($notable, 0, 3);
?>
<div class="vp-rw-in vp-rw-ports">
    <div class="vp-rw-metric">
        <span class="vp-rw-metric-n"><?=
            h(number_format($data['count'])) ?></span>
        <span class="vp-rw-metric-l"><?= h(__n(
            'open port', 'open ports', $data['count']
        )) ?></span>
    </div>
    <ul class="vp-rw-set">
        <?php foreach ($shown as $service): ?>
            <li class="<?= !empty($service['service'])
                && isset($notable[0]) ? 'vp-rw-hot' : '' ?>">
                <span class="font-monospace"><?=
                    h($service['port']) ?></span><?php
                if ($service['service'] !== null): ?>
                <span class="vp-rw-code"><?=
                    h($service['service']) ?></span>
            <?php endif; ?></li>
        <?php endforeach; ?>
    </ul>
    <?php if (!empty($notable)): ?>
        <div class="vp-rw-note vp-rw-split"><?= h(sprintf(
            __n('%s notable', '%s notable', count($notable)),
            count($notable)
        )) ?></div>
    <?php endif; ?>
</div>
