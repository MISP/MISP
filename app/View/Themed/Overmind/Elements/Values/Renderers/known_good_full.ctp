<?php
/**
 * The whole record, every field the service returned.
 *
 * Drawn as it came rather than reshaped. This is the one shape whose
 * full form has no argument to make beyond completeness: an analyst
 * dismissing a hash on the strength of a package record wants to see
 * the record, including the other hashes, because those are what they
 * will check it against.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-known">
    <?php foreach ($data['records'] as $record): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <?php if ($record['malicious'] !== null): ?>
                    <span class="vp-rw-verdict vp-rw-v-mal"><?=
                        h(__('known bad')) ?></span>
                <?php else: ?>
                    <span class="vp-rw-verdict vp-rw-v-ben"><?=
                        h(__('known good')) ?></span>
                <?php endif; ?>
                <?php if ($record['name'] !== null): ?>
                    <span class="vp-rf-name font-monospace"><?=
                        h($record['name']) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $record['module'])
                    ) ?></span>
            </div>
            <dl class="vp-rf-pairs">
                <?php foreach ($record['fields'] as $key => $value): ?>
                    <dt><?= h($key) ?></dt>
                    <dd class="<?= strpos($key, 'SHA') === 0
                        || $key === 'MD5' || $key === 'SSDEEP'
                        || $key === 'TLSH'
                        ? 'font-monospace' : '' ?>"><?=
                        h($value) ?></dd>
                <?php endforeach; ?>
            </dl>
        </div>
    <?php endforeach; ?>
</div>
