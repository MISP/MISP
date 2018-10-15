<div class="events">
    <?php echo $this->Form->create('User');?>
        <fieldset>
            <legend><?php echo __('Filter User Index');?></legend>
            <div class="overlay_spacing">
            <?php
                echo $this->Form->input('rule', array(
                        'options' => $rules,
                        //'empty' => '(Select a filter)',
                        'class' => 'input',
                        //'label' => 'Add Filtering Rule',
                        'onchange' => "indexRuleChange();",
                        'style' => 'margin-right:3px;width:120px;',
                        'div' => false
                ));

                echo $this->Form->input('searchbool', array(
                        'options' => array("OR", "NOT"),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:62px;margin-right:3px',
                        'div' => false
                ));

                foreach ($differentFilters as $b) {
                    echo $this->Form->input('search' . $b, array(
                        'options' => array('' => 'Any', '0' => 'No', '1' => 'Yes'),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:503px;',
                        'div' => false
                    ));
                }

                foreach ($simpleFilters as $t) {
                    if ($t == 'role') {
                        echo $this->Form->input('search' . $t, array(
                                'options' => array($roles),
                                'label' => false,
                                'class' => 'input-large',
                                'style' => 'display:none;width:438px;',
                                'div' => false
                        ));
                    } else if ($t == 'org') {
                        echo $this->Form->input('search' . $t, array(
                                'options' => array($orgs),
                                'label' => false,
                                'class' => 'input-large',
                                'style' => 'display:none;width:438px;',
                                'div' => false
                        ));
                    } else {
                        echo $this->Form->input('search' . $t, array(
                                'label' => false,
                                'class' => 'input-large',
                                'style' => 'display:none;width:424px;',
                                'div' => false
                        ));
                    }
                }
            ?>
            <span id="addRuleButton" class="btn btn-inverse" style="margin-bottom:10px;display:none;"><?php echo __('Add');?></span>
            </div>
        </fieldset>
        <div class="overlay_spacing">
        <?php echo $this->Form->end();?>
        <div id="rule_table">
            <table style="background-color:white;">
                <tr style="width:680px;background-color:#0088cc;color:white;">
                    <th style="width:100px;border:1px solid #cccccc;text-align: left;"><?php echo __('Target');?></th>
                    <th style="width:567px;border:1px solid #cccccc;border-right:0px;text-align: left;"><?php echo __('Value');?></th>
                    <th style="width:10px;border:1px solid #cccccc;border-left:0px;text-align: left;"></th>
                </tr>
                <?php
                    $fields = array_merge($differentFilters, $simpleFilters);
                    foreach ($fields as $k => $field):
                ?>
                    <tr id="row_<?php echo $field; ?>" class="hidden filterTableRow">
                        <td id="key_<?php echo $field;?>" style="border:1px solid #cccccc;font-weight:bold;"><?php echo ucfirst($field); ?></td>
                        <td id="value_<?php echo $field;?>" style="border:1px solid #cccccc;border-right:0px;"></td>
                        <td id="delete_<?php echo $field;?>" style="border:1px solid #cccccc;border-left:0px;"><span class="icon-trash" title="<?php echo __('Remove filter');?>" role="button" tabindex="0" aria-label="<?php echo __('Remove filter');?>" onClick="indexFilterClearRow('<?php echo $field;?>');"></span></td>
                    </tr>
                <?php
                    endforeach;
                ?>
            </table>
            <table style="background-color:white;width:100%;" id="FilterplaceholderTable">
                <tr class="filterTableRow">
                    <td style="border:1px solid #cccccc;border-top:0px;font-weight:bold;width:100%;color:red;"><?php echo __('No filters set - add filter terms above.');?></td>
                </tr>
            </table>
        </div>
        <?php echo $this->Form->create('User', array('id' => 'test', 'url' => $baseurl . '/admin/users/index'));?>
        <fieldset>
        <?php
            echo $this->Form->input('generatedURL', array(
                'label' => false,
                'class' => 'input',
                'style' => 'width:620px;display:none;',
                'div' => false
            ));
        ?>
        </fieldset>
        <div id = "generatedURL" style="word-wrap: break-word;"><br /><?php echo __('Save this URL if you would like to use the same filter settings again');?><br /><div style="background-color:#f5f5f5;border: 1px solid #e3e3e3; border-radius:4px;padding:3px;background-color:white;"><span id="generatedURLContent"></span></div></div>
        <br />
        <span role="button" tabindex="0" aria-label="<?php echo __('Apply filters');?>" title="<?php echo __('Apply filters');?>" class="btn btn-primary" onClick="indexApplyFilters();"><?php echo __('Apply');?></span>
        <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" class="btn btn-inverse" onClick="cancelPopoverForm();" style="float:right;"><?php echo __('Cancel');?></span>
        </div>
</div>
<script type="text/javascript">
var formInfoValues = {};

var typeArray = {
        'role' : <?php echo $roleJSON; ?>,
}

var filterContext = "user";

var showorg = <?php echo $showorg; ?>;

var filtering = <?php echo $filtering; ?>;

var operators = ["OR", "NOT"];

var differentFilters = ["autoalert", "contactalert", "termsaccepted"];

var simpleFilters = <?php echo json_encode($simpleFilters, true); ?>;

var typedFields = ["role"];

var orgs = <?php echo json_encode($orgs, true); ?>

var allFields = simpleFilters.concat(differentFilters);

var baseurl = "<?php echo $baseurl; ?>";

$(document).ready(function() {
    indexRuleChange();
    indexSetTableVisibility();
    indexEvaluateFiltering();
});
</script>
<?php echo $this->Js->writeBuffer();
