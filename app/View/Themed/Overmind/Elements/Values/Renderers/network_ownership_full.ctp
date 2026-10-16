<?php
/**
 * Every autonomous system claimed for this value, and everything each
 * announces.
 *
 * The compact form says one prefix; this is where the rest are, and a
 * long prefix list is the whole reason the full form exists — an
 * address inside a /20 belongs to a different kind of holder from one
 * inside a /32.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-asn">
    <?php foreach ($data['systems'] as $as): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <span class="font-monospace vp-rf-key"><?=
                    h($as['asn']) ?></span>
                <?php if ($as['holder'] !== null): ?>
                    <span class="vp-rf-name"><?=
                        h($as['holder']) ?></span>
                <?php endif; ?>
                <?php if ($as['country'] !== null): ?>
                    <span class="vp-rf-dim"><?=
                        h($as['country']) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $as['sources'])
                    ) ?></span>
            </div>
            <?php if ($as['first'] !== null || $as['last'] !== null): ?>
                <?php
                /*
                 * An announcement window, where the source carried one.
                 * It is the difference between a holder who has had
                 * this range for fifteen years and one who took it
                 * over last month.
                 */
                ?>
                <div class="vp-rf-sub"><?= h(sprintf(
                    __('announced %1$s — %2$s'),
                    $as['first'] === null
                        ? '?' : date('Y-m-d', $as['first']),
                    $as['last'] === null
                        ? '?' : date('Y-m-d', $as['last'])
                )) ?></div>
            <?php endif; ?>
            <?php if (empty($as['prefixes'])): ?>
                <p class="vp-rf-note"><?= h(
                    __('No prefixes were returned for this system.')
                ) ?></p>
            <?php else: ?>
                <ul class="vp-rf-prefixes">
                    <?php foreach ($as['prefixes'] as $prefix): ?>
                        <li class="font-monospace"><?=
                            h($prefix) ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
