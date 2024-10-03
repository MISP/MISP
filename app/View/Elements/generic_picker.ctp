<?php
/**
*   Generic select picker
*/
    /** Config **/
    $defaults_options = array(
        'select_options' => array(
            // 'multiple' => '', // set to add possibility to pick multiple options in the select
            //'placeholder' => '' // set to replace the default placeholder text
            // additionalData => '' // Additional data valid for all options which will be passed to the callback functionName
        ),
        'chosen_options' => array(
            'width' => '85%',
            'search_contains' => true, // matches starting from anywhere within a word
            //'no_results_text' => '', // set to replace the default no result text after filtering
            //'max_selected_options' => 'Infinity' // set to replace the max selected options
            'disable_search_threshold' => 10,
            'allow_single_deselect' => true,
        ),
        'multiple' => 'multiple',
        'select_threshold' => 7, // threshold above which pills will be replace by a select (unused if multiple is > 1)
        'functionName' => '', // function to be called on submit
        'submitButtonText' => 'Submit',
        'disabledSubmitButton' => false, // wether to not draw the submit button
        'flag_redraw_chosen' => false, // should chosen picker be redraw at drawing time
        'redraw_debounce_time' => 200,
        'autofocus' => true,
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
    if ($defaults['multiple'] != -1) {
        unset($defaults['select_options']['multiple']);
    } else { // multiple enabled
        $defaults['chosen_options']['max_selected_options'] = $defaults['multiple'] == -1 ? 'Infinity' : $defaults['multiple'];
        $defaults['select_options']['multiple'] = '';
        $defaults['select_threshold'] = 0;
    }
    $use_select = count($items) > $defaults['select_threshold'];
    $countThresholdReached = count($items) > 1000;
    $option_templates = array();
    $options_additionalData = array();
?>

<style>
.popover[data-dismissid] {
    max-width: 60%;
}
</style>

<script>
function execAndClose(elem) {
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
                var $select = $(this);
                var endpoint;
                if (selected !== undefined) {
                    endpoint = selected.selected;
                } else { //  for obscure reasons, `selected` variable is not set in some cases
                    endpoint = $(event.target).val();
                }
                if (endpoint === '') {
                    var $wrapper = $select.closest('div').find('div.generic-picker-wrapper');
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
    $elem.on('chosen:searchdone chosen:picked keyup change', function(e) {
        redrawChosenWithTemplateDebounced(true, $elem, $chosenContainer, e.type)
    });

    if (redrawChosen) {
        redrawChosenWithTemplateDebounced(false, $elem, $chosenContainer);
    }

    if ($elem.prop('multiple')) {
        $elem.filter('[autofocus]').trigger('chosen:open');
    } else {
        $elem.filter('[autofocus]').trigger('chosen:activate');
    }

    // Hide popover when pressing ESC on closed chosen
    $chosenContainer.on('keydown', function (e) {
        if (e.keyCode === 27 && !$chosenContainer.hasClass('chosen-with-drop')) {
            execAndClose($elem);
        }
    });
}

var debounceTimer;
function redrawChosenWithTemplateDebounced(useDebounce, $select, $chosenContainer, eventType) {
    if (useDebounce) {
        clearTimeout(debounceTimer);
        var timerValue = <?= $defaults['redraw_debounce_time'] ?>;
        var resultCount = $select.data('chosen').search_results.children().length;
        if (resultCount <= 20) {
            timerValue = 0
        }
        debounceTimer = setTimeout(function() {
            redrawChosenWithTemplate($select, $chosenContainer, eventType);
        }, timerValue);
    } else {
        redrawChosenWithTemplate($select, $chosenContainer, eventType);
    }
}

function redrawChosenWithTemplate($select, $chosenContainer, eventType) {
    var optionLength = $select.find('option').length;
    if (optionLength > 1000) {
        $chosenContainer.parent().find('.generic-picker-wrapper-warning-text').show(0)
    } else {
        $chosenContainer.find('.generic-picker-wrapper-warning-text').hide(0)
        var $matches;
        if (eventType === 'chosen:picked' || eventType === 'change') {
            $matches = $chosenContainer.find('.chosen-single > span, .search-choice > span');
        } else {
            $matches = $chosenContainer.find('.chosen-results .active-result');
        }
        var templates = options_templates[$select.attr('id')];
        $matches.each(function() {
            var $item = $(this);
            var index = $item.data('option-array-index');
            var $option;
            if (index !== undefined) {
                $option = $select.find('option:eq(' + index + ')');
            } else { // if it is a `chosen-single span`, don't have index
                var text = $item.text();
                $option = $select.find('option').filter(function() {
                    var temp = $.trim($(this).text());
                    return temp === text;
                });
            }
            var template = templates[$option.val()];
            if (template !== undefined && template !== '') {
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
        success:function (data) {
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
    var selected, additionalDataOption;
    var $clicked = $(clicked);
    var $select = $clicked.parent().find('select');
    if ($select.length == 0) {
        $select = $clicked.parent().parent().find('select');
        selected = $clicked.attr('value');
    } else {
        selected = $select.val();
    }
    if (selected === null) {
        showMessage('fail', '<?php echo __('No item picked'); ?>');
        return;
    }

    var additionalData = $select.data('additionaldata');
    if (additionalData === undefined) {
        additionalData = {};
    }
    additionalDataOption = options_additionalData[$select.attr('id')];
    additionalData['itemOptions'] = additionalDataOption;
    // callback function defined in the controller can be overridden in the JS
    var dismissId = $clicked.closest('.popover[data-dismissid]').data('dismissid');
    var callingButton = $('button[data-dismissid="' + dismissId + '"]');
    if (callingButton.data('popover-no-submit') && callingButton.data('popover-callback-function') !== undefined) {
        var callbackFunction = callingButton.data('popover-callback-function');
        execAndClose(clicked);
        callbackFunction(selected, additionalData);
    } else {
        execAndClose(clicked);
        callback(selected, additionalData);
    }
}
</script>
<div class="generic_picker">
    <div class="generic-picker-wrapper-warning-text alert alert-error<?= $countThresholdReached ? '' : ' hidden' ?>" style="margin-bottom: 5px;">
        <i class="fa fa-exclamation-triangle"></i>
        <?php echo __('Due to the large number of options, no contextual information is provided.'); ?>
    </div>
    <?php
    $select_id = 'gp_' . dechex(mt_rand()); // used to only register the listener on this select (allowing nesting)
    $flag_addPills = false;
    ?>
    <?php if ($use_select): ?>
        <select id="<?php echo $select_id; ?>"<?= $defaults['autofocus'] ? ' autofocus' : '' ?> style="margin-bottom: 0" <?= $this->GenericPicker->add_select_params($defaults); ?>>
            <option></option>
            <?php
                foreach ($items as $param) {
                    if (isset($param['isPill']) && $param['isPill']) {
                        $flag_addPills = true;
                    } else {
                        echo $this->GenericPicker->add_option($param);
                        if (!$countThresholdReached && isset($param['template'])) {
                            $template = $this->GenericPicker->build_template($param);
                            $option_templates[$param['value']] = $template;
                        }
                        if (isset($param['additionalData'])) {
                            $additionalData = $param['additionalData'];
                            $options_additionalData[$param['value']] = $additionalData;
                        }
                    }
                }
            ?>
        </select>
        <?php if ($defaults['multiple'] != 0 && !$defaults['disabledSubmitButton']): ?>
            <button class="btn btn-primary" onclick="submitFunction(this, <?php echo h($defaults['functionName']); ?>)"><?php echo h($defaults['submitButtonText']); ?></button>
        <?php endif; ?>

        <?php if ($flag_addPills): // add forced pills ?>
            <ul class="nav nav-pills">
                <?php
                foreach ($items as $param) {
                    if (isset($param['isPill']) && $param['isPill']) {
                        echo $this->GenericPicker->add_pill($param, $defaults);
                        if (isset($param['additionalData'])) {
                            $additionalData = $param['additionalData'];
                            $options_additionalData[$param['value']] = $additionalData;
                        }
                    }
                }
                ?>
            </ul>
        <?php endif; ?>

        <script>
            $(function() {
                setupChosen("<?php echo $select_id; ?>", <?php echo ($defaults['flag_redraw_chosen'] === true ? 'true' : 'false') ?>);
            });
        </script>

    <?php elseif (!empty($items)): ?>
        <ul class="nav nav-pills">
            <select id="<?php echo $select_id; ?>"<?= $defaults['autofocus'] ? ' autofocus' : '' ?> style="display: none;" <?php echo $this->GenericPicker->add_select_params($defaults); ?>></select>
            <?php
            foreach ($items as $param) {
                echo $this->GenericPicker->add_pill($param, $defaults);
                if (isset($param['additionalData'])) {
                    $additionalData = $param['additionalData'];
                    $options_additionalData[$param['value']] = $additionalData;
                }
            }
            ?>
        </ul>
    <?php else: ?>
        <span style="margin-left: 15px;"><?php echo __('Nothing to pick'); ?></span>
    <?php endif; ?>

    <div class="generic-picker-wrapper hidden"></div>

    <script>
        if (options_templates === undefined) {
            var options_templates = {};
            var options_additionalData = {};
        }
        // Keep as string, it is faster than parsing as JS
        options_templates['<?php echo $select_id; ?>'] = JSON.parse('<?= addslashes(json_encode($option_templates, JSON_UNESCAPED_UNICODE)); ?>');
        options_additionalData['<?php echo $select_id; ?>'] = JSON.parse('<?= addslashes(json_encode($options_additionalData, JSON_UNESCAPED_UNICODE)); ?>');
    </script>
</div>
