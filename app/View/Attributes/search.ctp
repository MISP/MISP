<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('url' => array('controller' => 'attributes', 'action' => 'search', 'results')));?>
    <fieldset>
        <legend><?php echo __('Search Attribute'); ?></legend>
<?php echo __('You can search for attributes based on contained expression within the value, event ID, submitting organisation, category and type. <br />For the value, event ID and organisation, you can enter several search terms by entering each term as a new line. To exclude things from a result, use the NOT operator (!) in front of the term.'); ?>
        <br />
<?php echo __('For string searches (such as searching for an expression, tags, etc) - lookups are simple string matches. If you want a substring match encapsulate the lookup string between "%" characters.'); ?>
        <br /><br />
        <?php
            echo $this->Form->input('value', array('type' => 'textarea', 'rows' => 2, 'label' => __('Containing the following expressions'), 'div' => 'clear', 'class' => 'input-xxlarge', 'required' => false));
            echo $this->Form->input('tags', array('type' => 'textarea', 'rows' => 2, 'label' => __('Having tag or being an attribute of an event having the tag'), 'div' => 'clear', 'class' => 'input-xxlarge', 'required' => false));
            echo $this->Form->input('uuid', array('type' => 'textarea', 'rows' => 2, 'maxlength' => false, 'label' => __('Being attributes of the following event IDs, event UUIDs or attribute UUIDs'), 'div' => 'clear', 'class' => 'input-xxlarge', 'required' => false));
            echo $this->Form->input('org', array(
                    'type' => 'textarea',
                    'label' => __('From the following organisation(s)'),
                    'div' => 'input clear',
                    'rows' => 2,
                    'class' => 'input-xxlarge'));
            echo $this->Form->input('type', array(
                'div' => 'input clear',
                'required' => false
            ));
            echo $this->Form->input('category', array('required' => false));
        ?>
            <div class="input clear"></div>
        <?php
            echo $this->Form->input('to_ids', array(
                'type' => 'checkbox',
                'label' => __('Only find IOCs flagged as to IDS')
            ));
            echo $this->Form->input('alternate', array(
                    'type' => 'checkbox',
                    'label' => __('Alternate Search Result (Events)')
            ));
            echo $this->Form->input('first_seen', array(
                'type' => 'text',
                'div' => 'input hidden',
                'required' => false,
            ));
            echo $this->Form->input('last_seen', array(
                'type' => 'text',
                'div' => 'input hidden',
                'required' => false,
            ));
        ?>
        <div class="clear">
        <h3><?php echo __('First seen and Last seen'); ?></h3>
        <p><?php echo __('Attributes not having first seen or last seen set might not appear in the search'); ?></p>
    </div>
    </fieldset>
    <?php echo $this->Form->end(); ?>
    <div id="bothSeenSliderContainer"></div>
    <button onclick="$('#AttributeSearchForm').submit();" class="btn btn-primary">Submit</button>
</div>
<?php echo $this->element('form_seen_input'); ?>
<script type="text/javascript">
var category_type_mapping = <?= json_encode(array_map(function($value) {
    return array_combine($value['types'], $value['types']);
}, $categoryDefinitions)); ?>;

//
// Generate Type / Category filtering array
//
var type_category_mapping = new Array();

<?php
// all categories for Type ALL
echo "type_category_mapping['ALL'] = {'ALL': 'ALL'";
foreach ($categoryDefinitions as $type => $def) {
        echo ", '" . addslashes($type) . "': '" . addslashes($type) . "'";
}
echo "}; \n";

// Categories per Type
foreach ($typeDefinitions as $type => $def) {
    echo "type_category_mapping['" . addslashes($type) . "'] = {'ALL': 'ALL'";
    foreach ($categoryDefinitions as $category => $def) {
        if ( in_array ( $type , $def['types'])) {
            echo ", '" . addslashes($category) . "': '" . addslashes($category) . "'";
        }
    }
    echo "}; \n";
}
?>

function formTypeChanged() {
    var alreadySelected = $('#AttributeCategory').val();
    // empty the categories
    $('option', $('#AttributeCategory')).remove();
    // add new items to options
    var options = $('#AttributeCategory').prop('options');
    $.each(type_category_mapping[$('#AttributeType').val()], function(val, text) {
        options[options.length] = new Option(text, val);
        if (val == alreadySelected) {
            options[options.length-1].selected = true;
        }
    });
    // enable the form element
    $('#AttributeCategory').prop('disabled', false);
}

var formInfoValues = new Array();
<?php
foreach ($typeDefinitions as $type => $def) {
    $info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
    echo "formInfoValues['$type'] = \"$info\";\n";
}

foreach ($categoryDefinitions as $category => $def) {
    $info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
    echo "formInfoValues['$category'] = \"$info\";\n";
}
$this->Js->get('#AttributeCategory')->event('change', 'formCategoryChanged("Attribute")');
$this->Js->get('#AttributeType')->event('change', 'formTypeChanged()');
?>

formInfoValues[''] = '';


$(function() {

    $("#AttributeType, #AttributeCategory").on('mouseleave', function(e) {
        $('#'+e.currentTarget.id).popover('destroy');
    });

    $("#AttributeType, #AttributeCategory").on('mouseover', function(e) {
        var $e = $(e.target);
        if ($e.is('option')) {
            $('#'+e.currentTarget.id).popover('destroy');
            $('#'+e.currentTarget.id).popover({
                trigger: 'manual',
                placement: 'right',
                content: formInfoValues[$e.val()],
            }).popover('show');
        }
    });

    // workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
    // disadvantage is that user needs to click on the item to see the tooltip.
    // no solutions exist, except to generate the select completely using html.
    $("#AttributeType, #AttributeCategory").on('change', function(e) {
        var $e = $(e.target);
        $('#'+e.currentTarget.id).popover('destroy');
        $('#'+e.currentTarget.id).popover({
            trigger: 'manual',
            placement: 'right',
            content: formInfoValues[$e.val()],
        }).popover('show');
    });

});
$('.input-xxlarge').keydown(function (e) {
      if (e.ctrlKey && e.keyCode == 13) {
          $('#AttributeSearchForm').submit();
      }
});
</script>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'searchAttributes'));
    echo $this->Js->writeBuffer();
?>
