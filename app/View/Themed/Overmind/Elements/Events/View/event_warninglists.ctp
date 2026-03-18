<?php
/**
 * AJAX-loaded warninglist hit summary for view2.
 *
 * Variables: $warninglistHits, $event
 */
?>
<div id="warninglistHitsContainer">
<?php
$hasHits = (
    !empty($warninglistHits['false_positive']) ||
    !empty($warninglistHits['known'])
);
if ($hasHits):
?>
    <?php if (
        !empty($warninglistHits['false_positive'])
    ): ?>
    <div class="warning_container false_positive"
         style="margin-bottom:10px;">
        <h4><?= __(
            'Potential false positives'
        ) ?></h4>
        <ul style="list-style:none;padding-left:5px;">
        <?php foreach (
            $warninglistHits['false_positive']
            as $id => $name
        ): ?>
            <li style="margin-bottom:3px;">
                <a href="<?=
                    $baseurl . '/warninglists/view/'
                    . (int)$id
                ?>">
                    <?= h($name) ?>
                </a>
            </li>
        <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>

    <?php if (
        !empty($warninglistHits['known'])
    ): ?>
    <div class="warning_container known_identifier"
         style="margin-bottom:10px;">
        <h4><?= __(
            'Known identifiers'
        ) ?></h4>
        <ul style="list-style:none;padding-left:5px;">
        <?php foreach (
            $warninglistHits['known']
            as $id => $name
        ): ?>
            <li style="margin-bottom:3px;">
                <a href="<?=
                    $baseurl . '/warninglists/view/'
                    . (int)$id
                ?>">
                    <?= h($name) ?>
                </a>
            </li>
        <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>
<?php else: ?>
    <p><em><?= __(
        'No warninglist hits for this event.'
    ) ?></em></p>
<?php endif; ?>
</div>
