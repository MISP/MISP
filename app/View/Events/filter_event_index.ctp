<style>
.tag-search-results {
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    border-radius: 4px;
    background: white;
}

.tag-result-item:hover {
    background-color: #f5f5f5;
}

.tag-result-item:last-child {
    border-bottom: none !important;
}

.tag-search-input {
    position: relative;
}
</style>

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
                        'style' => 'margin-right:3px;width:130px;',
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
                        'style' => 'width:438px;',
                        'div' => false
                ));
                if ($showorg) {
                    echo $this->Form->input('searchorg', array(
                            'options' => $orgs,
                            'class' => 'input',
                            'label' => false,
                            'style' => 'width:438px;',
                            'div' => false
                    ));
                }
                echo $this->Form->input('searchtag', array(
                        'type' => 'text',
                        'class' => 'input tag-search-input',
                        'label' => false,
                        'style' => 'width:438px',
                        'div' => false,
                        'placeholder' => __('Type to search tags...'),
                        'autocomplete' => 'off'
                ));
                echo '<div id="tag-search-results" class="tag-search-results" style="display:none; position:absolute; z-index:1000; background:white; border:1px solid #ccc; max-height:200px; overflow-y:auto; width:438px;"></div>';
                echo $this->Form->input('searchdatefrom', array(
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

                echo $this->Form->input('searchtimestampfrom', array(
                    'class' => 'input',
                    'label' => false,
                    'style' => 'display:none;width:236px;margin-right:3px;',
                    'div' => false,
                    'placeholder' => __("YYYY-MM-DD HH:mm:ss")
                ));

                echo $this->Form->input('searchtimestampuntil', array(
                    'class' => 'input',
                    'label' => false,
                    'style' => 'display:none;width:236px;margin-right:3px;',
                    'div' => false,
                    'placeholder' => __("YYYY-MM-DD HH:mm:ss")
                ));

                echo $this->Form->input('searchpublishtimestampfrom', array(
                    'class' => 'input',
                    'label' => false,
                    'style' => 'display:none;width:236px;margin-right:3px;',
                    'div' => false,
                    'placeholder' => __("YYYY:MM:DD HH:MM:SS")
                ));

                echo $this->Form->input('searchpublishtimestampuntil', array(
                    'class' => 'input',
                    'label' => false,
                    'style' => 'display:none;width:236px;margin-right:3px;',
                    'div' => false,
                    'placeholder' => __("YYYY:MM:DD HH:MM:SS")
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
                echo $this->Form->input('searchall', array(
                        'label' => false,
                        'class' => 'input-large',
                        'style' => 'display:none;width:424px;',
                        'div' => false
                ));
                echo $this->Form->input('searchextending', array(
                    'options' => array('0' => __('No'), '1' => __('Yes'), '2' => __('Any')),
                    'class' => 'input',
                    'label' => false,
                    'style' => 'display:none;width:503px;',
                    'div' => false
                ));
                echo $this->Form->input('searchextended', array(
                    'options' => array('0' => __('No'), '1' => __('Yes'), '2' => __('Any')),
                    'class' => 'input',
                    'label' => false,
                    'style' => 'display:none;width:503px;',
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
                        $fields = array('published', 'org', 'tag', 'date', 'eventinfo', 'eventid', 'threatlevel', 'analysis', 'is_extension', 'is_extended', 'distribution', 'sharinggroup', 'attribute', 'hasproposal', 'timestamp', 'publishtimestamp', 'all');
                        if ($isSiteAdmin) $fields[] = 'email';
                        foreach ($fields as $k => $field):
                    ?>
                        <tr id="row_<?php echo $field; ?>" class="hidden filterTableRow">
                            <td id="key_<?php echo $field;?>" style="border:1px solid #cccccc;font-weight:bold;"><?php echo ucfirst($field); ?></td>
                            <td id="value_<?php echo $field;?>" style="border:1px solid #cccccc;border-right:0px;"></td>
                            <td id="delete_<?php echo $field;?>" style="border:1px solid #cccccc;border-left:0px;"><span class="fa fa-trash" title="<?php echo __('Delete filter');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete filter');?>" onClick="indexFilterClearRow('<?php echo $field;?>')"></span></td>
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
        'tag' : [], // Tags will be loaded dynamically via AJAX
        'published' : [<?php echo __('"No"');?>, "<?php echo __('Yes');?>", "<?php echo __('Any');?>"],
        'is_extension' : [<?php echo __('"No"');?>, "<?php echo __('Yes');?>", "<?php echo __('Any');?>"],
        'is_extended' : [<?php echo __('"No"');?>, "<?php echo __('Yes');?>", "<?php echo __('Any');?>"],
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

var extendsOptions = ["<?php echo __('No');?>", "<?php echo __('Yes');?>", "<?php echo __('Any');?>"];

var filtering = <?php echo $filtering; ?>;

var operators = ["<?php echo __('OR');?>", "<?php echo __('NOT');?>"];

var allFields = ["published", "tag", "date", "eventinfo", "eventid", "threatlevel", "distribution", "sharinggroup", "analysis", "attribute", "hasproposal", "timestamp", "publishtimestamp", "extending", "extended", "all"];

var simpleFilters = ["tag", "eventinfo", "eventid", "threatlevel", "distribution", "sharinggroup", "analysis", "attribute", "all"];

var differentFilters = ["published", "date", "hasproposal", "timestamp", "publishtimestamp", "extending", "extended"];

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

$(function() {
    $('.datepicker').datepicker().on('changeDate', function(ev) {
        $('.dropdown-menu').hide();
    });
    $('#EventSearchorg, #EventSearchsharinggroup').chosen();
    $('#EventSearchorg_chosen, #EventSearchsharinggroup_chosen').css('top', '-5px');
    
    // Initialize dynamic tag search functionality
    initTagSearch();
    
    indexEvaluateFiltering();
});

// Dynamic tag search functionality
function initTagSearch() {
    var searchTimeout;
    var $tagInput = $('.tag-search-input');
    var $tagResults = $('#tag-search-results');
    
    $tagInput.on('input', function() {
        var query = $(this).val().trim();
        
        // Clear previous timeout
        clearTimeout(searchTimeout);
        
        if (query.length < 2) {
            $tagResults.hide();
            return;
        }
        
        // Debounce the search to avoid excessive API calls
        searchTimeout = setTimeout(function() {
            searchTags(query);
        }, 300);
    });
    
    // Handle tag selection
    $tagResults.on('click', '.tag-result-item', function() {
        var tagId = $(this).data('tag-id');
        var tagName = $(this).data('tag-name');
        
        // Set the selected tag
        $tagInput.val(tagName);
        $tagResults.hide();
        
        // Add the tag to the filtering
        addTagToFilter(tagId, tagName);
    });
    
    // Hide results when clicking outside
    $(document).on('click', function(e) {
        if (!$(e.target).closest('.tag-search-input, .tag-search-results').length) {
            $tagResults.hide();
        }
    });
}

function searchTags(query) {
    $.ajax({
        url: baseurl + '/tags/search/' + encodeURIComponent(query),
        method: 'GET',
        dataType: 'json',
        success: function(data) {
            displayTagResults(data);
        },
        error: function() {
            console.error('Failed to search tags');
        }
    });
}

function displayTagResults(tags) {
    var $tagResults = $('#tag-search-results');
    var html = '';
    
    if (tags.length === 0) {
        html = '<div class="tag-result-item no-results" style="padding: 8px; color: #666;">No tags found</div>';
    } else {
        tags.forEach(function(tag) {
            html += '<div class="tag-result-item" data-tag-id="' + tag.Tag.id + '" data-tag-name="' + tag.Tag.name + '" style="padding: 8px; cursor: pointer; border-bottom: 1px solid #eee;">' + 
                    '<span style="color: #' + (tag.Tag.colour || '000000') + ';">' + tag.Tag.name + '</span>' +
                    '</div>';
        });
    }
    
    $tagResults.html(html).show();
}

function addTagToFilter(tagId, tagName) {
    // This function integrates with the existing filtering system
    // You may need to adjust this based on how the existing filter system works
    console.log('Tag selected:', tagId, tagName);
    
    // Example: Add to the filtering array
    if (!typeArray.tag.some(function(tag) { return tag.id == tagId; })) {
        typeArray.tag.push({ id: tagId, value: tagName });
    }
}

</script>
<?php echo $this->Js->writeBuffer();
 