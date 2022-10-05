<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('url' => array('controller' => 'attributes', 'action' => 'search', 'results')));?>
    <fieldset>
        <legend><?php echo __('Search Attribute'); ?></legend>
        <?= __('You can search for attributes based on contained expression within the value, event ID, submitting organisation, category and type. <br>For the value, event ID and organisation, you can enter several search terms by entering each term as a new line. To exclude things from a result, use the NOT operator (!) in front of the term.'); ?>
        <br>
        <?= __('For string searches (such as searching for an expression, tags, etc) - lookups are simple string matches. If you want a substring match encapsulate the lookup string between "%" characters.'); ?>
        <br><br>
        <?php
            echo $this->Form->input('value', array('type' => 'textarea', 'rows' => 2, 'label' => __('Containing the following expressions'), 'div' => 'clear', 'class' => 'input-xxlarge', 'required' => false));
            echo $this->Form->input('tags', array('type' => 'textarea', 'rows' => 2, 'label' => __('Having tag or being an attribute of an event having the tag'), 'div' => 'clear', 'class' => 'input-xxlarge', 'required' => false));
            echo $this->Form->input('uuid', array('type' => 'textarea', 'rows' => 2, 'maxlength' => false, 'label' => __('Being attributes of the following event IDs, event UUIDs or attribute UUIDs'), 'div' => 'clear', 'class' => 'input-xxlarge', 'required' => false));
            echo $this->Form->input('org', array(
                'type' => 'textarea',
                'label' => __('From the following organisation(s)'),
                'div' => 'input clear',
                'rows' => 2,
                'class' => 'input-xxlarge'
            ));
            $typeFormInfo = $this->element('genericElements/Form/formInfo', [
                'field' => [
                    'field' => 'type'
                ],
                'modelForForm' => 'Attribute',
                'fieldDesc' => $fieldDesc['type'],
            ]);
            echo $this->Form->input('type', array(
                'div' => 'input clear',
                'required' => false,
                "label" => __("Type") . " " . $typeFormInfo,
            ));
            $categoryFormInfo = $this->element('genericElements/Form/formInfo', [
                'field' => [
                    'field' => 'category'
                ],
                'modelForForm' => 'Attribute',
                'fieldDesc' => $fieldDesc['category'],
            ]);
            echo $this->Form->input('category', array(
                'required' => false,
                "label" => __("Category") . " " . $categoryFormInfo,
            ));
        ?>
            <div class="input clear"></div>
        <?php
            echo $this->Form->input('to_ids', array(
                'type' => 'checkbox',
                'label' => __('Only find IOCs flagged as to IDS'),
                'div' => ['style' => 'margin-top:1em'],
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
    <div id="bothSeenSliderContainer"></div>
    <div class="clear"></div>
    <button class="btn btn-primary" style="margin-top: 1em" type="submit"><?= __("Search") ?></button>
    <?php echo $this->Form->end(); ?>
</div>
<?php echo $this->element('form_seen_input'); ?>
<script>
var category_type_mapping = <?= json_encode(array_map(function(array $value) {
    return $value['types'];
}, $categoryDefinitions)); ?>;

function searchFormTypeChanged() {
    var $categorySelect = $('#AttributeCategory');
    var alreadySelected = $categorySelect.val();
    // empty the categories
    $('option', $categorySelect).remove();
    // add new items to options
    var options = $categorySelect.prop('options');
    var selectedType = $('#AttributeType').val();

    $.each(category_type_mapping, function (category, types) {
        if (types.indexOf(selectedType) !== -1) {
            var option = new Option(category, category);
            if (category === alreadySelected) {
                option.selected = true;
            }
            options.add(option);
        }
    });
    // enable the form element
    $categorySelect.prop('disabled', false);
}

$(function() {
    $('#AttributeCategory, #AttributeType').chosen();

    $("#AttributeCategory").change(function () {
        formCategoryChanged("Attribute");
        $("#AttributeType").trigger("chosen:updated");
    }).change();

    $("#AttributeType").change(function () {
        searchFormTypeChanged();
        $("#AttributeCategory").trigger("chosen:updated");
    }).change();
});
</script>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'searchAttributes'));
