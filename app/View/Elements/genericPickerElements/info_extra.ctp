
<?php if (!is_array($infoExtra)): ?>
    <?php if (strlen($infoExtra) < 50 && !(isset($forceIcon) && $forceIcon)): ?>
        <i style="float:right; font-size: smaller;margin-right: 5px;"><?php echo h($infoExtra); ?></i>
    <?php else: ?>
        <it class="fa fa-info-circle generic-picker-item-element-info" style="float:right;margin-left: 5px;line-height:13px;" title="<?php echo h($infoExtra); ?>"></it>
    <?php endif; ?>

<?php elseif (isset($infoExtra['type'])): // same as if infoExtra is not an array ?>
    <?php if ($infoExtra['type'] === 'text'): ?>
        <?php if (strlen($infoExtra) < 50 && !(isset($forceIcon) && $forceIcon)): ?>
            <i style="float:right;font-size: smaller;margin-right: 5px;"><?php echo h($infoExtra); ?></i>
        <?php else: ?>
            <it class="fa fa-info-circle generic-picker-item-element-info" style="float:right;line-height:13px;margin-left: 5px;" title="<?php echo h($infoExtra); ?>"></it>
        <?php endif; ?>

    <?php elseif ($infoExtra['type'] === 'check'): ?>
        <?php $checkType = isset($infoExtra['checked']) && $infoExtra['checked'] == true ? 'fa-check' : 'fa-times'; ?>
        <?php $checkColor = isset($infoExtra['checked']) && $infoExtra['checked'] == true ? '#449d44' : '#c9302c'; ?>
        <it class="generic-picker-item-element-check" style="background-color: <?php echo $checkColor; ?>">
            <it>
                <?php echo isset($infoExtra['text']) ? h($infoExtra['text']) : ""; ?>
            </it>
            <it style="margin-right: 0px;line-height:13px;" class="fa <?php echo $checkType; ?>"></it>
        </it>

    <?php elseif ($infoExtra['type'] === 'table'): ?>

    <?php endif; ?>
<?php endif; ?>
