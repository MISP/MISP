<?php
/**
 * Facts body: each key with its values as chips; a single short value sits
 * on the key's line.
 */
$rc = $this->RailCard;
?>
<dl class="rcard-facts">
    <?php foreach ($rc->factRows($card) as $row): ?>
        <div class="rcard-fact<?= count($row['values']) === 1 && empty($row['more']) ? ' rcard-fact-single' : '' ?>">
            <dt class="rcard-fact-label"><?= h($row['label']) ?></dt>
            <dd class="rcard-chips">
                <?php foreach ($row['values'] as $value): ?>
                    <?php
                    $content = '<span class="rcard-chip-label">' . h($value['text']) . '</span>';
                    if (!empty($value['href']) && preg_match('#^https?://#i', $value['href'])) {
                        $content .= '<i class="fas fa-arrow-up-right-from-square rcard-chip-ext" aria-hidden="true"></i>';
                    }
                    echo $rc->link(
                        $value['href'],
                        'rcard-chip rcard-chip-fact' . (empty($value['href']) ? '' : ' rcard-chip-link'),
                        $content,
                        $value['href'] ?: $value['text']
                    );
                    ?>
                <?php endforeach; ?>
                <?= $rc->moreChip($row['more'], $card, $tab) ?>
            </dd>
        </div>
    <?php endforeach; ?>
</dl>
