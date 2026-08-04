<?php
$colorMapping = [
    0 => '#cc0033',
    1 => '#f89406',
];
?>

<h2><?= __('Preventive Measures & Mitigations') ?></h2>
<?php foreach (array_values($course_of_action) as $i => $coa) : ?>
    <div style="margin-bottom: 0.5em;">
        <div>
            <span class="tag" style="background-color: <?= $colorMapping[$i] ?? '#999' ?>; color: #fff; border-radius: 9px; padding: 2px 8px;">
                <?= h($coa['occurrence']) ?>
            </span>
            <strong><a href="<?= $baseurl . '/galaxy_clusters/view/' . h($coa['id']) ?>" target="_blank"><?= h($coa['value']) ?></a>: </strong>
            <?= h($this->Markdown->toText($coa['description'])) ?>
        </div>
        <ul>
            <?php foreach ($coa['techniques'] as $technique) : ?>
                <li>
                    <code><?= h($technique['value']) ?></code>:
                    <small><?= h($technique['description']) ?></small>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endforeach; ?>