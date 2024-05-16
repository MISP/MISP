<?php
/*
* Matrix Generator
* Params:
    Required
    --------

        - $tabs: Contains the matrix data. Has the format:
            {
                tab1: {
                    col1: [
                        {rowData1}, {rowData2}, ...
                    ],
                    col2: [
                        {rowData1}, {rowData2}, ...
                    ]
                },
                tab2: {}
            }

    Optional
    --------
        - $defaultTabName: Set the default active tab. Default value is first tab
        - $columnOrders: Defined the order of the column in each tabs. Has the format:
            {
                tab1: [col1, col2],
                tab2: [col1, col2]
            }
        - $interpolation: The color associated to each value. Has the format: { val1: [r, g, b], val2: [r, g, b] }
        - $maxScore:
        - $pickingMode: Interactive picking mode, add a form and the chosen input
        - $scores: The score associate with either the value or the tag name (if provided)
        - $removeTrailling: How much part of the name of the cell should be remove: e.g. $removeTrailling=2 => "abc def ghi", will be: "abc"
        - $colours: The colour associated with the tag name (if provided)
        - $static: Should the output be inert. Used for embedding in other webpages or mails
*
*
*
*/
if (!empty($static)) {
    $pickingMode = false;
}

if (empty($static)) {
    echo $this->element('genericElements/assetLoader', [
        'css' => ['attack_matrix'],
        'js' => ['attack_matrix'],
    ]);
}
$clustersNamesMapping = array(); // used to map name with id for the chosen select
if (isset($interpolation) && !empty($interpolation)) {
    foreach ($interpolation as $k => $colArr) {
        $col = str_pad(dechex($colArr[0]), 2, '0', STR_PAD_LEFT) . str_pad(dechex($colArr[1]), 2, '0', STR_PAD_LEFT) . str_pad(dechex($colArr[2]), 2, '0', STR_PAD_LEFT);
        $interpolation[$k] = '#' . $col;
        if ($k == 0) { // force small area on white
            $interpolation[$k] .= ' 3%';
        }
    }
    $colorScale = implode(', ', $interpolation);
} else {
    $colorScale = 'black';
}
?>

<?php if (empty($static)): ?>
<div class="attack-matrix-options" style="right: initial; background: transparent;">
<ul id="attack-matrix-tabscontroller" class="nav nav-tabs" style="margin-bottom: 2px;">
<?php
if (!isset($defaultTabName)) {
    reset($columnOrders);
    $defaultTabName = key($columnOrders); // get first key
}

if (empty($static)):
foreach(array_keys($columnOrders) as $tabName):
?>
<?php $column = $tabs[$tabName]; ?>
    <li class="tactic <?php echo $tabName==$defaultTabName ? "active" : ""; ?>"><span href="#tabMatrix-<?php echo h($tabName); ?>" data-toggle="tab" style="padding-top: 3px; padding-bottom: 3px;"><?php echo h($tabName); ?></span></li>
<?php endforeach; ?>
<?php endif; ?>
</ul>
</div>
<?php endif; ?>

<?php if (empty($static)): ?>
<div class="attack-matrix-options matrix-div-submit submit-container">
    <span class="btn btn-inverse btn-matrix-submit" role="button" tabindex="0" style="padding: 1px 5px !important;font-size: 12px !important;font-weight: bold;"><?php echo __('Submit'); ?></span>
</div>
<?php endif; ?>

<?php if (empty($static)): ?>
<div class="attack-matrix-options">
    <?php if (isset($interpolation)): ?>
    <span id="matrix-heatmap-legend-caret">
    <span id="matrix-heatmap-legend-caret-value">0</span>
    <span class="fa fa-caret-down"></span>
    </span>
    <div>
        <span>0</span>
        <div id="matrix-heatmap-legend" style="background: linear-gradient(to right, white 0%, <?php echo h($colorScale); ?>);"></div>
        <span id="matrix-heatmap-maxval"><?php echo h($maxScore); ?></span>
    </div>
    <?php endif; ?>
    <label style="display: inline-block; margin-left: 30px;"><input type="checkbox" id="checkbox_attackMatrix_showAll" checked><i class="fa fa-filter"></i><?= __('Show all') ?></label>
</div>
<?php endif; ?>

<?php if (isset($eventId) && empty($static)): ?>
<div class="hidden">
    <?php
        $url = sprintf(
            '%s/galaxies/attachMultipleClusters/%s/%s/local:%s',
            $baseurl,
            empty($target_id) ? $eventId : $target_id,
            empty($target_type) ? 'event' : $target_type,
            empty($local) ? '0' : '1'
        );

        echo $this->Form->create('Galaxy', array('url' => $url));
        echo $this->Form->input('target_ids', array('label' => false));
        echo $this->Form->input('attribute_ids', array('label' => false));
        echo $this->Form->end();
    ?>
</div>
<?php endif; ?>

<div id="matrix_container" class="fixed-table-container-inner" style="" data-picking-mode="<?php echo $pickingMode ? 'true' : 'false'; ?>">
    <div class="tab-content">
    <?php foreach(array_keys($columnOrders) as $tabName): ?>
        <?php $column = $tabs[$tabName]; ?>
        <?php
        if (!empty($static) && $tabName != $defaultTabName) {
            // We cannot hide other tabs without JS. Only releave the default one for now.
            continue;
        }
        ?>
        <div class="tab-pane <?php echo $tabName==$defaultTabName ? "active" : ""; ?>" id="tabMatrix-<?php echo h($tabName); ?>">
        <div class="header-background"></div>
        <div class="fixed-table-container-inner" style="overflow-y: auto; max-height: 670px;">
        <table class="table table-condensed matrix-table">
        <thead style="background-color: #363636;">
        <tr>
        <?php
            foreach($columnOrders[$tabName] as $co):
                $name = str_replace("-", " ", $co);
        ?>
            <th>
                <?php echo empty($static) ? h(ucfirst($name)) : ''; ?>
                <div class="th-inner" style="flex-direction: column; align-items: flex-start; padding-top: 3px; color: white;">
                    <span><?php echo h(ucfirst($name)); ?></span>
                </div>
            </th>

        <?php endforeach; ?>
        </tr>
        </thead>
        <tbody style="overflow-y: scroll;">
            <?php
                $added = false;
                $i = 0;
                do {
                    $tr = '<tr>';
                    $added = false;
                    foreach ($columnOrders[$tabName] as $co) {
                        if (isset($column[$co][$i])) {
                            $added = true;
                            $td = '<td';
                            $cell = $column[$co][$i];
                            if (!is_array($cell)) {
                                $cell = array('value' => $cell);
                            }
                            $value = isset($cell['value']) ? $cell['value'] : 0;
                            if (isset($removeTrailling) && $removeTrailling > 0) {
                                $name = explode(" ", $value);
                                $name = join(" ", array_slice($name, 0, -$removeTrailling)); // remove " - external_id"
                            } else {
                                $name = $value;
                            }
                            $tagName = isset($cell['tag_name']) ? $cell['tag_name'] : $name;
                            $score = empty($scores[$tagName]) ? 0 : $scores[$tagName];
                            $clusterId = isset($cell['id']) ? $cell['id'] : $name;
                            $externalId = isset($cell['external_id']) ? $cell['external_id'] : '';

                            $title = h($externalId);
                            if (empty($static) && !empty($cell['description'])) {
                                $shortDescription = $this->Markdown->toText($cell['description']);
                                if (strlen($shortDescription) > 1000) {
                                    $shortDescription = mb_substr($shortDescription, 0, 1000) . '[...]';
                                }
                                $title .= ': &#10;' . h($shortDescription);
                            }

                            $clustersNamesMapping[$clusterId] = $name . ($externalId !== '' ? ' (' . $externalId. ')' : '');

                            $td .= ' class="heatCell matrix-interaction ' . ($pickingMode ? 'cell-picking"' : '"');
                            $td .= isset($colours[$tagName]) ? ' style="background: ' . h($colours[$tagName]) . '; color: ' . $this->TextColour->getTextColour($colours[$tagName]) . '"' : '' ;
                            $td .= ' data-score="'.h($score).'"';
                            $td .= ' data-tag_name="'.h($tagName).'"';
                            $td .= ' data-cluster-id="'.h($clusterId).'"';
                            if ($pickingMode) {
                                $td .= ' data-target-type="attribute"';
                                $td .= ' data-target-id="'.h($target_id).'"';
                            }
                            $td .= ' title="' . $title . '"';
			                $td .= ' tabindex="0" aria-label="' . h($externalId) . '"';
                            $td .= '>' . h($name);

                        } else { // empty cell
                            $td = '<td style="border: none;">';
                        }
                        $td .=  '</td>';
                        $tr .= $td;
                    }
                    $tr .= '</tr>';
                    echo $tr;
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
<?php if ($pickingMode): ?>
<div style="padding: 5px;">
    <select id="attack-matrix-chosen-select" style="width: 100%; margin: 0px;" multiple>
        <?php
        foreach ($clustersNamesMapping as $clusterId => $clusterName) {
            echo '<option value=' . h($clusterId) .'>' . h($clusterName) . '</option>';
        }
        ?>
    </select>
</div>
<div class="templateChoiceButton btn-matrix-submit submit-container hide"><?php echo __('Submit'); ?></div>
<div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onclick="cancelPopoverForm('#popover_matrix');"><?php echo __('Cancel'); ?></div>
<?php endif; ?>
