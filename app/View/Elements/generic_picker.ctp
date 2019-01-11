<?php
/**
*   Generic select picker
*/
    /** Config **/
    $select_threshold = 6; // threshold on which pills will be replace by a select (unused if multiple is > 1)
    $defaults_options = array(
        'select_options' => array(
            // 'multiple' => '', // set to add possibility to pick multiple options in the select
            //'placeholder' => '' // set to replace the default placeholder text
        ),
        'chosen_options' => array(
            'width' => '400px',
            'search_contains' => true, // matches starting from anywhere within a word
            //'no_results_text' => '', // set to replace the default no result text after filtering
            //'max_selected_options' => 'Infinity' // set to replace the max selected options
            'disable_search_threshold' => 10,
            'allow_single_deselect' => true,
        ),
        'multiple' => 0,
        'functionName' => '', // function to be called on submit
    );
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

    function add_select_params($options) {
        $select_html = '';
        foreach ($options['select_options'] as $option => $value) {
            $select_html .= $option . '=' . $value . ' ';
        }
        return $select_html;
    }

    function add_option($name, $param) {
        $option_html = '<option';
        if (is_array($param)) {
            if (isset($param['value'])) {
                $option_html .= ' value=' . h($param['value']);
            } else {
                $option_html .= ' value=' . h($name);
            }
            if (isset($param['additionalData'])) {
                $additionalData = json_encode($param['additionalData']);
            } else {
                $additionalData = json_encode(array());
            }

            if (isset($param['template'])) {
                $option_html .= ' data-template=' . base64_encode($param['template']);
            }
            if (isset($param['templateData'])) {
                $option_html .= ' data-templatedata=' . base64_encode(json_encode($param['templateData']));
            }
            debug($param['templateData']);

            $option_html .= ' data-additionaldata=' . $additionalData;

            if (in_array('disabled', $param)) {
                $option_html .= ' disabled';
            } else if (in_array('selected', $param)) { // nonsense to pre-select if disabled
                $option_html .= ' selected';
            }
        } else {
            $option_html .= ' value=' . h($param);
        }
        $option_html .= '>';

        // $option_html .= is_array($param)? h($name) : h($param);
        $option_html .= h($name);
        $option_html .= '</option>';
        return $option_html;
    }

    function add_link_params($name, $param, $defaults=array()) {
        $param_html = ' ';
        if (is_array($param)) { // add data as param
            if (isset($param['functionName'])) {
                // $param_html .= 'onclick="' . $param['functionName'] . '" ';
                $param_html .= 'onclick="execAndClose(this, ' . $param['functionName'] . ')" ';
            } else { // fallback to default submit function
                $param_html .= 'onclick="submitFunction(this, ' . $defaults['functionName'] . ')" ';
            }

            $additionalData = json_encode(array());
            foreach ($param as $paramName => $paramValue) {
                if ($paramName === 'additionalData') {
                    $additionalData = json_encode($param['additionalData']);
                } else if ($paramName === 'value'){
                    $param_html .= 'value="' . h($paramValue) . '" ';
                } else {
                    $param_html .= 'data-' . h($paramName). '="' . h($paramValue) . '" ';
                }
            }
            $param_html .= ' data-additionaldata=' . $additionalData;
        } else { // param is a simple endpoint from which fetch data
            $param_html .= 'data-endpoint="' . h($param) . '" ';
            $param_html .= 'onclick="fetchRequestedData(this)" ';
        }
        return $param_html;
    }

    function add_pill($name, $param, $defaults=array()) {
        $pill_html = '<li>';
        $pill_html .= '<a href="#" data-toggle="pill" class="pill-pre-picker"';
        $pill_html .= ' ' . add_link_params($name, $param, $defaults);
        $pill_html .= '>';
        if (isset($param['img'])) {
            $pill_html .= '<img src="' . $param['img'] . '" style="margin-right: 5px; height: 14px;">';
        } else if (isset($param['icon'])) {
            $pill_html .= '<span class="fa ' . $param['icon'] . '" style="margin-right: 5px;"></span>';
        }
        $pill_html .= h($name) . '</a>';
        $pill_html .= '</li>';
        return $pill_html;
    }
?>

<script>
function execAndClose(elem, alreadyExecuted) {
    $(elem).closest('div.popover').prev().popover('destroy');
}

function setupChosen(id) {
    var $elem = $('#'+id);
    var chosen_options = <?php echo json_encode($defaults['chosen_options']); ?>;
    $elem.chosen(chosen_options);
    if (!$elem.prop('multiple')) { // not multiple, selection trigger next event
        $elem.change(function(event, selected) {
            select = this;
            $select = $(select);
            $select.data('endpoint', selected.selected);
            fetchRequestedData($select);
        });
    }

    // hack to add template into the div
    $elem.on('chosen:showing_dropdown keyup change', function() {
        var $chosenContainer = $elem.parent().find('.chosen-container');
        $chosenContainer
            .find('.chosen-results .active-result, .chosen-single span')
            .html(function() {
                var $item = $(this);
                var index = $item.data('option-array-index');
                var $option;
                if (index !== undefined) {
                    $option = $elem.find('option:eq(' + index + ')');
                } else {
                    var text = $item.text();
                    $option = $elem.find('option:contains(' + text + ')');
                }
                var template = $option.data('template');
                if (template !== undefined && template !== '') {
                    var template = atob(template);
                    var temp = doT.template(template);
                    var templateData = JSON.parse(atob($option.data('templatedata')));
                    var res = temp(templateData);
                    return res;
                }
            });
    });
}

// Used to keep the popover arrow at the correct place regardless of the popover content
function syncPopoverArrow($arrow, $wrapper, content) {
    var ar_pos = $arrow.position();
    $wrapper.html(content);
    $wrapper.show();
    // redraw popover
    $arrow.css('top', ar_pos.top + 'px');
    $arrow.css('left', ar_pos.left + 'px');
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
    callback(selected, additionalData);
}
</script>

<div class="generic_picker">
    <?php if ($use_select): ?>
        <?php
        $select_id = h(uniqid()); // used to only register the listener on this select (allowing nesting)
        $flag_addPills = false;
        ?>
        <select id="<?php echo $select_id; ?>" style="height: 20px; margin-bottom: 0px;" <?php echo h(add_select_params($defaults)); ?>>
            <option></option>
            <?php
                foreach ($items as $name => $param) {
                    if (isset($param['isPill']) && $param['isPill']) {
                        $flag_addPills = true;
                        continue;
                    } else {
                        echo add_option($name, $param);
                    }
                }
            ?>
        </select>
        <?php if ($defaults['multiple'] != 0): ?>
            <button class="btn btn-primary" onclick="submitFunction(this, <?php echo $defaults['functionName']; ?>)">submit</button>
        <?php endif; ?>

        <?php if ($flag_addPills): // add forced pills ?>
            <ul class="nav nav-pills">
                <?php foreach ($items as $name => $param): ?>
                    <?php if (isset($param['isPill']) && $param['isPill']):  ?>
                        <?php echo add_pill($name, $param, $defaults); ?>
                    <?php endif; ?>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <script>
            $(document).ready(function() {
                setupChosen("<?php echo $select_id; ?>");
            });
        </script>

    <?php else: ?>
        <ul class="nav nav-pills">
            <?php foreach ($items as $name => $param): ?>
                <?php echo add_pill($name, $param, $defaults); ?>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>

    <div class='generic-picker-wrapper hidden'></div>

</div>
