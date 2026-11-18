<?php
/**
 * The line inside an object's header button, shared by the list view's
 * accordion and the card view so the two never drift.
 *
 * Left: distribution, then the template name (with its meta-category and
 * version) over the first attribute's value. Right: attribute count, last
 * change.
 *
 * Parameters:
 *   object     array  one entry of $objects
 *   ctx        array  see $objContext in Elements/Objects/index.ctp. Only
 *                     count / deleted / firstValue / firstRelation are read, so a
 *                     caller outside the index can build a small one.
 *   asideHtml  string optional raw HTML appended to the right-hand slot, for a
 *                     surface with something of its own to put there (the
 *                     enrichment review's reference count and remove button).
 *                     Escape it yourself.
 */
$dist = $this->DistributionLevel->get((int)($object['distribution'] ?? 0));
$count = (int)$ctx['count'];
$timestamp = (int)($object['timestamp'] ?? 0);
$firstTitle = ($ctx['firstRelation'] !== '' ? $ctx['firstRelation'] . ': ' : '')
    . $ctx['firstValue'];
?>
<span class="ov-obj-head">

    <span class="ov-obj-dist"
          style="--ov-dist-bg:<?= h($dist['bg']) ?>;--ov-dist-ink:<?= h($dist['color']) ?>;"
          title="<?= h(__('Distribution: %s', $dist['label'])) ?>">
        <i class="<?= h($dist['icon']) ?>"></i>
    </span>

    <span class="ov-obj-title">
        <span class="ov-obj-name">
            <span class="text-truncate"><?= h($object['name']) ?></span>
            <?php if (!empty($object['meta-category']) || !empty($object['template_version'])): ?>
                <span class="ov-obj-meta"
                      title="<?= h(__('Meta-category') . (!empty($object['template_version'])
                          ? ' · ' . __('Template v%s', $object['template_version']) : '')) ?>">
                    <?php if (!empty($object['meta-category'])): ?>
                        <?= h($object['meta-category']) ?>
                    <?php endif; ?>
                    <?php if (!empty($object['template_version'])): ?>
                        <span class="ov-obj-meta-version"><?= __('v%s', h($object['template_version'])) ?></span>
                    <?php endif; ?>
                </span>
            <?php endif; ?>
            <?php if ($ctx['deleted']): ?>
                <span class="ov-obj-deleted">
                    <i class="fas fa-trash"></i><?= __('Deleted') ?>
                </span>
            <?php endif; ?>
        </span>
        <?php if ($ctx['firstValue'] !== ''): ?>
            <span class="ov-obj-first" title="<?= h($firstTitle) ?>">
                <?php if ($ctx['firstRelation'] !== ''): ?>
                    <span class="ov-obj-first-rel"><?= h($ctx['firstRelation']) ?></span>
                <?php endif; ?>
                <span class="ov-obj-first-val"><?= h($ctx['firstValue']) ?></span>
            </span>
        <?php endif; ?>
    </span>

    <span class="ov-obj-aside">
        <span class="ov-obj-count"
              title="<?= h(__n('%s attribute', '%s attributes', $count, $count)) ?>">
            <span class="misp-icon misp-icon-attribute misp-simple"></span>
            <?= $count ?>
        </span>
        <?php if ($timestamp > 0): ?>
            <span class="ov-obj-date"
                  title="<?= h(__('Last modified: %s', date('Y-m-d H:i:s', $timestamp))) ?>">
                <i class="far fa-calendar"></i>
                <?= date('Y-m-d', $timestamp) ?>
            </span>
        <?php endif; ?>
        <?php if (!empty($asideHtml)): ?>
            <?= $asideHtml ?>
        <?php endif; ?>
    </span>

</span>
