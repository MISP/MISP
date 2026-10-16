<?php
/**
 * A record's changed fields, one row each: the field, what it was, what
 * it becomes.
 *
 * @var array $changes List of `field`, `was`, `is`; an empty side is a
 *     field that was not set, or is being cleared
 * @var string $class Extra classes on the table
 */
$class = $class ?? '';
?>
<table class="vp-audit-diff<?= $class === '' ? '' : ' ' . h($class) ?>">
    <?php foreach ($changes as $change): ?>
        <tr>
            <th><?= h($change['field']) ?></th>
            <td>
                <?php if ($change['was'] === ''): ?>
                    <em class="text-muted"><?= __('not set') ?></em>
                <?php else: ?>
                    <s><?= h($change['was']) ?></s>
                <?php endif; ?>
            </td>
            <td><i class="fas fa-arrow-right"></i></td>
            <td>
                <?php if ($change['is'] === ''): ?>
                    <em class="text-muted"><?= __('cleared') ?></em>
                <?php else: ?>
                    <?= h($change['is']) ?>
                <?php endif; ?>
            </td>
        </tr>
    <?php endforeach; ?>
</table>
