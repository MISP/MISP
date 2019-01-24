<?php
/**
*   Generic select picker
*/
    /** Config **/
    $select_threshold = 7; // threshold above which pills will be replace by a select (unused if multiple is > 1)
    $defaults_options = array(
        'select_options' => array(
            // 'multiple' => '', // set to add possibility to pick multiple options in the select
            //'placeholder' => '' // set to replace the default placeholder text
        ),
        'chosen_options' => array(
            'width' => '85%',
            'search_contains' => true, // matches starting from anywhere within a word
            //'no_results_text' => '', // set to replace the default no result text after filtering
            //'max_selected_options' => 'Infinity' // set to replace the max selected options
            'disable_search_threshold' => 10,
            'allow_single_deselect' => true,
        ),
        'multiple' => 0,
        'functionName' => '', // function to be called on submit
        'submitButtonText' => 'Submit',
        'disabledSubmitButton' => false, // wether to not draw the submit button
        'flag_redraw_chosen' => false // should chosen picker be redraw at drawing time
    );
    /**
    * Supported default option in <Option> fields:
    *   - name: The name of the item (will be used by the search algo)
    *   - value: The value when sent when the item is selected
    *   - template: The template to apply for custom chosen item
    *   - templateData: Data that will be passed to the template construction function
    *   - additionalData: Additional data to pass to the callback functionName
    */

    /** prevent exception if not set **/
    $options = isset($options) ? $options : array();
    $items = isset($items) ? $items : array();
    // merge options with defaults
    $defaults = array_replace_recursive($defaults_options, $options);

    // enforce consistency
    if ($defaults['multiple'] == 0) {
        unset($defaults['select_options']['multiple']);
    } else { // multiple enabled
        $defaults['chosen_options']['max_selected_options'] = $defaults['multiple'] == -1 ? 'Infinity' : $defaults['multiple'];
        $defaults['select_options']['multiple'] = '';
        $select_threshold = 0;
    }
    $use_select = count($items) > $select_threshold;
?>

<script>
function execAndClose(elem, alreadyExecuted) {
    var dismissid = $(elem).closest('div.popover').attr('data-dismissid');
    $('[data-dismissid="' + dismissid + '"]').popover('destroy');
}

function setupChosen(id, redrawChosen) {
    var $elem = $('#'+id);
    var chosen_options = <?php echo json_encode($defaults['chosen_options']); ?>;
    $elem.chosen(chosen_options);
    if (!$elem.prop('multiple')) { // not multiple, selection trigger next event
        $elem.change(function(event, selected) {
            var fn = $elem.data('functionname');
            if (fn !== undefined) {
                fn = window[fn];
                submitFunction(this, fn);
            } else {
                select = this;
                $select = $(select);
                var endpoint;
                if (selected !== undefined) {
                    endpoint = selected.selected;
                } else { //  for obscure reasons, `selected` variable is not set in some cases
                    endpoint = $(event.target).val();
                }
                if (endpoint === '') {
                    $wrapper = $select.closest('div').find('div.generic-picker-wrapper');
                    $wrapper.hide(0);
                } else {
                    $select.data('endpoint', endpoint);
                    fetchRequestedData($select);
                }
            }
        });
    }

    // hack to add template into the div
    var $chosenContainer = $elem.parent().find('.chosen-container');
    $elem.on('chosen:showing_dropdown chosen:searchdone chosen:picked keyup change', function() {
        redrawChosenWithTemplate($elem, $chosenContainer)
    });

    if (redrawChosen) {
        redrawChosenWithTemplate($elem, $chosenContainer);
    }
}

function redrawChosenWithTemplate($select, $chosenContainer) {
    var optionLength = $select.find('option').length;
    if (optionLength > 1000) {
        $chosenContainer.parent().find('.generic-picker-wrapper-warning-text').show(0)
    } else {
        $chosenContainer.find('.generic-picker-wrapper-warning-text').hide(0)
        var $matches = $chosenContainer.find('.chosen-results .active-result, .chosen-single > span, .search-choice > span');
        $matches.each(function() {
            var $item = $(this);
            var index = $item.data('option-array-index');
            var $option;
            if (index !== undefined) {
                $option = $select.find('option:eq(' + index + ')');
            } else { // if it is a `chosen-single span`, don't have index
                var text = $item.text();
                $option = $select.find('option:contains(' + text + ')');
            }
            var template = $option.data('template');
            var res = "";
            if (template !== undefined && template !== '') {
                var template = atob(template);
                $item.html(template);
            }
        })
    }
}

// Used to keep the popover arrow at the correct place regardless of the popover content
function syncPopoverArrow($arrow, $wrapper, content) {
    var ar_pos = $arrow.position();
    $wrapper.html(content);
    $wrapper.show();
    // redraw popover
    if (ar_pos !== undefined) {
        $arrow.css('top', ar_pos.top + 'px');
        $arrow.css('left', ar_pos.left + 'px');
    }
}

// can either call a function or fetch requested data
function fetchRequestedData(clicked) {
    var $clicked = $(clicked);
    var $wrapper = $clicked.closest('div').find('div.generic-picker-wrapper');
    $.ajax({
        dataType:"html",
        async: true,
        cache: false,
        beforeSend: function() {
            var loadingHtml = '<div style="height: 40px; width: 40px; left: 50%; position: relative;"><div class="spinner" style="height: 30px; width: 30px;"></div></div>';
            var $arrow = $clicked.closest('div.popover').find('div.arrow');
            var $wrapper = $clicked.closest('div').find('div.generic-picker-wrapper');
            syncPopoverArrow($arrow, $wrapper, loadingHtml)
        },
        success:function (data, textStatus) {
            $wrapper = $clicked.closest('div').find('div.generic-picker-wrapper');
            var $arrow = $clicked.closest('div.popover').find('div.arrow');
            syncPopoverArrow($arrow, $wrapper, data)
        },
        error:function() {
            $wrapper = $clicked.closest('div').find('div.generic-picker-wrapper');
            $wrapper.html('<div class="alert alert-error" style="margin-bottom: 0px;">Something went wrong - the queried function returned an exception. Contact your administrator for further details (the exception has been logged).</div>');
        },
        url: $clicked.data('endpoint')
    });
}

function submitFunction(clicked, callback) {
    var $clicked = $(clicked);
    var $select = $clicked.parent().find('select');
    var selected, additionalData;
    if ($select.length > 0) {
        selected = $select.val();
        additionalData = $select.find(":selected").data('additionaldata');
    } else {
        selected = $clicked.attr('value');
        additionalData = $clicked.data('additionaldata');
    }
    if (additionalData !== undefined) {
        additionalData = JSON.parse(atob(additionalData));
        execAndClose(clicked);
        callback(selected, additionalData);
    }
}
</script>

<div class="generic_picker">
    <div class='generic-picker-wrapper-warning-text alert alert-error <?php echo (count($items) > 1000 ? '' : 'hidden'); ?>' style="margin-bottom: 5px;">
        <i class="fa fa-exclamation-triangle"></i>
        <?php echo __('Due to the large number of options, no contextual information is provided.'); ?>
    </div>
    <?php if ($use_select): ?>
        <?php
        $select_id = h(uniqid()); // used to only register the listener on this select (allowing nesting)
        $flag_addPills = false;
        ?>
        <select id="<?php echo $select_id; ?>" style="height: 100px; margin-bottom: 0px;" <?php echo h($this->GenericPicker->add_select_params($defaults)); ?>>
            <option></option>
            <?php
                foreach ($items as $k => $param) {
                    if (isset($param['isPill']) && $param['isPill']) {
                        $flag_addPills = true;
                        continue;
                    } else {
                        echo $this->GenericPicker->add_option($param, $defaults);
                    }
                }
            ?>
        </select>
        <?php if ($defaults['multiple'] != 0 && !$defaults['disabledSubmitButton']): ?>
            <button class="btn btn-primary" onclick="submitFunction(this, <?php echo h($defaults['functionName']); ?>)"><?php echo h($defaults['submitButtonText']); ?></button>
        <?php endif; ?>

        <?php if ($flag_addPills): // add forced pills ?>
            <ul class="nav nav-pills">
                <?php foreach ($items as $k => $param): ?>
                    <?php if (isset($param['isPill']) && $param['isPill']):  ?>
                        <?php echo $this->GenericPicker->add_pill($param, $defaults); ?>
                    <?php endif; ?>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <script>
            $(document).ready(function() {
                setupChosen("<?php echo h($select_id); ?>", <?php echo ($defaults['flag_redraw_chosen'] === true ? 'true' : 'false') ?>);
            });
        </script>

    <?php elseif (count($items) > 0): ?>
        <ul class="nav nav-pills">
            <?php foreach ($items as $k => $param): ?>
                <?php echo $this->GenericPicker->add_pill($param, $defaults); ?>
            <?php endforeach; ?>
        </ul>
    <?php else: ?>
        <span style="margin-left: 15px;"><?php echo __('Nothing to pick'); ?></span>
    <?php endif; ?>

    <div class='generic-picker-wrapper hidden'></div>

</div>
