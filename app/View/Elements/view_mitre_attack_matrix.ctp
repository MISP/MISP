<div class="attack-matrix-options" style="right: initial; background: transparent;">
<ul id="attack-matrix-tabscontroller" class="nav nav-tabs" style="margin-bottom: 2px;">
<?php
$enterpriseTag = "mitre-enterprise-attack-attack-pattern";
foreach($attackTactic as $tactic):
    $galaxy = $tactic['galaxy'];
?>
    <li class="tactic <?php echo $galaxy['type']==$enterpriseTag ? "active" : ""; ?>"><span href="#tabMatrix-<?php echo h($galaxy['type']); ?>" data-toggle="tab" style="padding-top: 3px; padding-bottom: 3px;"><?php echo h($galaxy['name']); ?></span></li>
<?php endforeach; ?>
</ul>
</div>

<div class="attack-matrix-options matrix-div-submit">
    <span class="btn btn-inverse btn-matrix-submit" role="button" style="padding: 1px 5px !important;font-size: 12px !important;font-weight: bold;"><?php echo __('Submit'); ?></span>
</div>

<div class="attack-matrix-options">
    <span id="matrix-heatmap-legend-caret">
    <span id="matrix-heatmap-legend-caret-value">0</span>
    <span class="fa fa-caret-down"></span>
    </span>
    <div>
    <span>0</span>
    <div id="matrix-heatmap-legend"></div>
    <span id="matrix-heatmap-maxval"><?php echo h($maxScore); ?></span>
    </div>
    <label style="display: inline-block; margin-left: 30px;"><input type="checkbox" id="checkbox_attackMatrix_showAll" checked><span class="fa fa-filter"><?php echo __('Show all');?></span></input></label>
</div>

<div class="hidden">
    <?php
        echo $this->Form->create('Galaxy', array('url' => '/galaxies/attachMultipleClusters/' . (empty($target_id) ? $eventId : $target_id ) . '/' . (empty($target_type) ? 'event' : $target_type), 'style' => 'margin:0px;'));
        echo $this->Form->input('target_ids', array('type' => 'text'));
        echo $this->Form->end();
    ?>
</div>

<div id="matrix_container" class="fixed-table-container-inner" style="max-height: 670px;" data-picking-mode="<?php echo $pickingMode ? 'true' : 'false'; ?>">
    <div class="tab-content">
    <?php foreach($attackTactic as $galaxy):
    $galaxyType = $galaxy['galaxy']['type'];
    ?>
    <div class="tab-pane <?php echo $galaxyType==$enterpriseTag ? "active" : ""; ?>" id="tabMatrix-<?php echo h($galaxyType); ?>">
    <div class="header-background"></div>
    <div class="fixed-table-container-inner" style="max-height: 670px;">
    <table class="table table-condensed matrix-table">
    <thead>
    <tr>
    <?php
        foreach($killChainOrders[$galaxyType] as $kc):
            $name = str_replace("-", " ", $kc);
    ?>
        <th>
            <?php echo h(ucfirst($name)); ?>
            <div class="th-inner"><?php echo h(ucfirst($name)); ?></div>
        </th>

    <?php endforeach; ?>
    </tr>
    </thead>
    <tbody style="overflow-y: scroll;">
    <?php
        $added = false;
        $i = 0;
        do {
            $added = false;
            echo '<tr>';
                $killChainOrder = $killChainOrders[$galaxyType];
                $attackClusters = $galaxy['clusters'];
                foreach($killChainOrder as $kc) {
                    if(!isset($attackClusters[$kc])) { // undefined index
                        $td = '<td class="">';
                    } else {
                        $clusters = $attackClusters[$kc];
                        $td = '<td ';
                        if ($i < count($clusters)) {
                            $clusterId = $clusters[$i]['id'];
                            $tagName = $clusters[$i]['tag_name'];
                            $score = empty($scores[$tagName]) ? 0 : $scores[$tagName];
                            $name = join(" ", array_slice(explode(" ", $clusters[$i]['value']), 0, -2)); // remove " - external_id"
                            $td .= ' class="heatCell matrix-interaction ' . ($pickingMode ? 'cell-picking"' : '"');
                            $td .= isset($colours[$tagName]) ? ' style="background: ' . h($colours[$tagName]) . '; color: ' . h($this->TextColour->getTextColour($colours[$tagName])) . '"' : '' ;
                            $td .= ' data-score="'.h($score).'"';
                            $td .= ' data-tag_name="'.h($tagName).'"';
                            $td .= ' data-cluster-id="'.h($clusterId).'"';
                            if ($pickingMode) {
                                $td .= ' data-target-type="attribute"';
                                $td .= ' data-target-id="'.h($target_id).'"';
                            }
                            $td .= ' title="'.h($clusters[$i]['external_id']).'"';
                            $td .= '>' . h($name);
                            $added = true;
                        } else {
                            $td .= 'class="">';
                        }
                    }
                    $td .=  '</td>';
                    echo $td;
                }
            echo '</tr>';
            $i++;
        } while($added);
    ?>
    </tbody>
    </table>
    </div>
    </div>
    <?php endforeach; ?>
    </div>
</div>

<?php if($pickingMode): ?>
<div role="button" tabindex="0" aria-label="<?php echo __('Submit');?>" title="<?php echo __('Submit');?>" class="templateChoiceButton btn-matrix-submit" onClick="cancelPopoverForm('#popover_form_large');"><?php echo __('Submit'); ?></div>
<div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm('#popover_form_large');"><?php echo __('Cancel'); ?></div>
<?php endif; ?>

<?php
    echo $this->Html->script('bootstrap-typeahead');
    echo $this->Html->script('attack_matrix');
    echo $this->Html->css('attack_matrix');
?>
