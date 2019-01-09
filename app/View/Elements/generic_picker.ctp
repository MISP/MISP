<?php
/**
*   Generic select picker
*/
     // prevent exception if not set
    $options = isset($options) ? $options : array();
    $items = isset($items) ? $items : array();

    $defaults_options = array(
        'select_options' => array(
            // 'multiple' => '', // set to add possibility to pick multiple options in the select
            //'placeholder' => '' // set to replace the default placeholder text
        ),
        'chosen_options' => array(
            'width' => '400px',
            //'no_results_text' => '', // set to replace the default no result text after filtering
            //'max_selected_options' => 'Infinity' // set to replace the max selected options
            'disable_search_threshold' => 10,
            'allow_single_deselect' => true,
        ),
        'functionName' => '', // function to be called on submit
    );

    // merge options with defaults
    $defaults = array_replace_recursive($defaults_options, $options);

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

        $option_html .= is_array($param)? h($name) : h($param);
        $option_html .= '</option>';
        return $option_html;
    }

?>

<div class="popover_choice generic_picker">
    <div>
        <select <?php echo h(add_select_params($defaults)); ?>>
            <?php
                foreach ($items as $name => $param) {
                    echo add_option($name, $param);
                }
            ?>
        </select>
        <button class="btn btn-primary" onclick="submitFunction(this, <?php echo $defaults['functionName']; ?>)">submit</button>
    </div>
    <!-- <div class="overlay_spacing" style="margin: 5px; margin-top: 10px;"> -->
    <!-- </div> -->
</div>

<?php
    echo $this->Html->css('chosen.min');
    echo $this->Html->script('chosen.jquery.min');
?>
<script>
    $('document').ready(function() {
        var chosen_options = <?php echo json_encode($defaults['chosen_options']); ?>;
        $(".generic_picker select").chosen(chosen_options);
    })

    function submitFunction(clicked, callback) {
        var $clicked = $(clicked);
        var $select = $clicked.parent().find('select');
        var selected = $select.val();
        var additionalData = $select.find(":selected").data('additionaldata');
        callback(selected, additionalData);
    }
</script>
