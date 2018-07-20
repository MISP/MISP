<div class="events">
    <?php echo $this->Form->create('Event');?>
        <fieldset>
            <legend><?php echo __('Filter Event Index');?></legend>
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
                        'options' => array(__("OR"), __("NOT")),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:62px;margin-right:3px',
                        'div' => false
                ));

                echo $this->Form->input('searchpublished', array(
                        'options' => array('0' => __('No'), '1' => __('Yes'), '2' => __('Any')),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:503px;',
                        'div' => false
                ));
                echo $this->Form->input('searchthreatlevel', array(
                        'options' => array('1' => __('High'), '2' => __('Medium'), '3' => __('Low'), '4' => __('Undefined')),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:438px;',
                        'div' => false
                ));
                echo $this->Form->input('searchanalysis', array(
                        'options' => array('0' => __('Initial'), '1' => __('Ongoing'), '2' => __('Completed')),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:438px;',
                        'div' => false
                ));
                echo $this->Form->input('searchdistribution', array(
                        'options' => array('0' => __('Your organisation only'), '1' => __('This community only'), '2' => __('Connected communities'), '3' => __('All communities')),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:438px;',
                        'div' => false
                ));
                echo $this->Form->input('searchsharinggroup', array(
                        'options' => $sharingGroups,
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:438px;',
                        'div' => false
                ));
                if ($showorg) {
                    echo $this->Form->input('searchorg', array(
                            'options' => $orgs,
                            'class' => 'input',
                            'label' => false,
                            'style' => 'display:none;width:438px;',
                            'div' => false
                    ));
                }
                echo $this->Form->input('searchtag', array(
                        'options' => array($tags),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:438px;',
                        'div' => false
                ));
                echo $this->Form->input('searchdatefrom', array(
                        'div' => 'input clear',
                        'class' => 'datepicker',
                        'data-date-format' => 'yyyy-mm-dd',
                        'label' => false,
                        'style' => 'display:none;width:236px;margin-right:3px;',
                        'div' => false
                ));

                echo $this->Form->input('searchdateuntil', array(
                        'class' => 'datepicker',
                        'label' => false,
                        'data-date-format' => 'yyyy-mm-dd',
                        'style' => 'display:none;width:236px;',
                        'div' => false
                ));
                echo $this->Form->input('searcheventinfo', array(
                        'label' => false,
                        'class' => 'input-large',
                        'style' => 'display:none;width:424px;',
                        'div' => false
                ));
                if ($isSiteAdmin) {
                    echo $this->Form->input('searchemail', array(
                            'label' => false,
                            'class' => 'input-large',
                            'style' => 'display:none;width:424px;',
                            'div' => false
                    ));
                }
                echo $this->Form->input('searcheventid', array(
                        'label' => false,
                        'class' => 'input-large',
                        'style' => 'display:none;width:424px;',
                        'div' => false
                ));
                echo $this->Form->input('searchhasproposal', array(
                        'options' => array('0' => __('No'), '1' => __('Yes'), '2' => __('Any')),
                        'class' => 'input',
                        'label' => false,
                        'style' => 'display:none;width:503px;',
                        'div' => false
                ));
                echo $this->Form->input('searchattribute', array(
                        'label' => false,
                        'class' => 'input-large',
                        'style' => 'display:none;width:424px;',
                        'div' => false
                ));
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
                        $fields = array('published', 'org', 'tag', 'date', 'eventinfo', 'eventid', 'threatlevel', 'analysis', 'distribution', 'sharinggroup', 'attribute', 'hasproposal');
                        if ($isSiteAdmin) $fields[] = 'email';
                        foreach ($fields as $k => $field):
                    ?>
                        <tr id="row_<?php echo $field; ?>" class="hidden filterTableRow">
                            <td id="key_<?php echo $field;?>" style="border:1px solid #cccccc;font-weight:bold;"><?php echo ucfirst($field); ?></td>
                            <td id="value_<?php echo $field;?>" style="border:1px solid #cccccc;border-right:0px;"></td>
                            <td id="delete_<?php echo $field;?>" style="border:1px solid #cccccc;border-left:0px;"><span class="icon-trash" title="<?php echo __('Delete filter');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete filter');?>" onClick="indexFilterClearRow('<?php echo $field;?>')"></span></td>
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
            <?php echo $this->Form->create('Event', array('id' => 'test', 'url' => $baseurl . '/events/index'));?>
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
            <span role="button" tabindex="0" aria-label="<?php echo __('Apply');?>" title="<?php echo __('Apply');?>" class="btn btn-primary" onClick="indexApplyFilters();"><?php echo __('Apply');?></span>
            <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" onClick="cancelPopoverForm();" style="float:right;"><?php echo __('Cancel');?></span>
        </div>
</div>
<script type="text/javascript">
var formInfoValues = {};

var typeArray = {
        'tag' : <?php echo $tagJSON; ?>,
        'published' : [<?php echo __('"No"');?>, "<?php echo __('Yes');?>", "<?php echo __('Any');?>"],
        'hasproposal' : ["<?php echo __('No');?>", "<?php echo __('Yes');?>", "<?php echo __('Any');?>"],
        'distribution' : [
                        {"id" : "0", "value" : "<?php echo __('Your organisation only');?>"},
                        {"id" : "1", "value" : "<?php echo __('This community only');?>"},
                        {"id" : "2", "value" : "<?php echo __('Connected communities');?>"},
                        {"id" : "3", "value" : "<?php echo __('All communities');?>"}
                        ],
        'threatlevel' : [
                        {"id" : "1", "value" : "<?php echo __('High');?>"},
                        {"id" : "2", "value" : "<?php echo __('Medium');?>"},
                        {"id" : "3", "value" : "<?php echo __('Low');?>"},
                        {"id" : "4", "value" : "<?php echo __('Undefined');?>"}
                        ],
        'analysis' : [
                        {"id" : "0", "value" : "<?php echo __('Initial');?>"},
                        {"id" : "1", "value" : "<?php echo __('Ongoing');?>"},
                        {"id" : "2", "value" : "<?php echo __('Completed');?>"}
                    ]
};

var filterContext = "event";

var showorg = <?php echo $showorg == true ? 1 : 0; ?>;
var isSiteAdmin = <?php echo $isSiteAdmin == true ? 1 : 0; ?>;

var publishedOptions = ["<?php echo __('No');?>", "<?php echo __('Yes');?>", "<?php echo __('Any');?>"];

var hasproposalOptions = ["<?php echo __('No');?>", "<?php echo __('Yes');?>", "<?php echo __('Any');?>"];

var filtering = <?php echo $filtering; ?>;

var operators = ["<?php echo __('OR');?>", "<?php echo __('NOT');?>"];

var allFields = ["published", "tag", "date", "eventinfo", "eventid", "threatlevel", "distribution", "sharinggroup", "analysis", "attribute", "hasproposal"];

var simpleFilters = ["tag", "eventinfo", "eventid", "threatlevel", "distribution", "sharinggroup", "analysis", "attribute"];

var differentFilters = ["published", "date", "hasproposal"];

var typedFields = ["tag", "threatlevel", "distribution", "analysis"];

if (showorg == 1) {
    allFields.push("org");
    simpleFilters.push("org");
}

if (isSiteAdmin == 1) {
    allFields.push("email");
    simpleFilters.push("email");
}

var baseurl = "<?php echo $baseurl; ?>";

$(document).ready(function() {
    $('.datepicker').datepicker().on('changeDate', function(ev) {
        $('.dropdown-menu').hide();
    });
    indexEvaluateFiltering();
});

</script>
<?php echo $this->Js->writeBuffer();
