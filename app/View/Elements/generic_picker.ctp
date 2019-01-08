<?php
/**
*   Generic select picker from JSON
*   Required: $options, items
*/
    $defaults_options = array(
        'select_options' => array(
            // 'multiple' => '', // set to add possibility to pick multiple options in the select
            //'placeholder' => '' // set to replace the default placeholder text
        ),
        'chosen_options' => array(
            //'no_results_text' => '', // set to replace the default no result text after filtering
            //'max_selected_options' => 'Infinity' // set to replace the max selected options
            'disable_search_threshold' => 10,
            'allow_single_deselect' => true,
        ),
        'require_choice' => false,
        'pre_choices' => array()
    );
    $scope = isset($scope) ? $scope : '';

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
            if (in_array('disabled', $param)) {
                $option_html .= ' disabled';
            } else if (in_array('selected', $param)) { // nonsense to pre-select if disabled
                $option_html .= ' selected';
            }
        }
        $option_html .= ' value=' . (is_array($param)? h($name) : h($param));
        $option_html .= '>';

        $option_html .= is_array($param)? h($name) : h($param);
        $option_html .= '</option>';
        return $option_html;
    }

?>

<div class="popover_choice generic_picker">
    <legend><?php echo __(h($scope));?></legend>

    <select <?php echo h(add_select_params($defaults)); ?>>
        <?php
            foreach ($items as $name => $param) {
                echo add_option($name, $param);
            }
        ?>
    </select>

    <div class="overlay_spacing" style="margin: 5px; margin-top: 10px;">
        <button class="btn btn-primary" onclick="popoverPopup(this, '', 'events', 'genericPicker')">submit</button>
    </div>
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
</script>
