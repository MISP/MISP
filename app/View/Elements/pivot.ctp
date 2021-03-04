<?= $this->Html->css('tree'); ?>
<div>
    <div class="tree">
        <?= $this->Pivot->convertPivotToHTML($pivot, $event['Event']['id']); ?>
    </div>
    <div style="clear:both"></div>
</div>
