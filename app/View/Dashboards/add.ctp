<?php
    $modelForForm = 'Dashboard';
    $paramsHtml = '';
    if (!empty($data['params'])) {
        foreach ($data['params'] as $param => $desc) {
            $paramsHtml .= sprintf(
                '<span class="bold">%s</span>: %s<br />',
                h($param),
                h($desc)
            );
        }
    }
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'url' => 'updateSettings',
        'data' => array(
            'title' => __('Add Widget'),
            'model' => 'Dashboard',
            'fields' => array(
                array(
                    'field' => 'widget',
                    'class' => 'input span6',
                    'options' => Hash::combine($data['widget_options'], '{s}.widget', '{s}.title')
                ),
                array(
                    'field' => 'width',
                    'class' => 'input',
                    'type' => 'number',
                    'default' => 1,
                    'stayInLine' => 1
                ),
                array(
                    'field' => 'height',
                    'type' => 'number',
                    'class' => 'input',
                    'default' => 1
                ),
                array(
                    'field'=> 'config',
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __('Config')
                )
            ),
            'submit' => array(
                'action' => 'edit',
                'ajaxSubmit' => sprintf(
                    "submitDashboardAddWidget()"
                )
            ),
            'description' => '<p class="black widget-description"><span></p><p class="bold">Parameters</p><p class="widget-parameters"></p>'
        )
    ));
?>
<script type="text/javascript">
    var widget_options = <?= json_encode($data['widget_options']) ?>;

    function setDashboardWidgetChoice() {
        var current_choice = $('#DashboardWidget').val();
        var current_widget_data = widget_options[current_choice];
        $('#DashboardWidth').val(current_widget_data['width']);
        $('.widget-description').text(current_widget_data['description']);
        $('#DashboardHeight').val(current_widget_data['height']);
        $('#DashboardConfig').attr('placeholder', current_widget_data['placeholder']);
        $('.widget-parameters').empty();
        $.each(current_widget_data['params'], function(index,value) {
            $('.widget-parameters').append(
                $('<span>')
                .attr('class', 'bold')
                .text(index)
            ).append(
                $('<span>')
                .text(': ' + value)
            ).append(
                $('<br>')
            )
        });
        //$('#DashboardConfig').val(JSON.stringify(current_widget_data['params'], null, 2));
    }

    $('#DashboardWidget').change(function() {
        setDashboardWidgetChoice();
    });

    $(document).ready(function() {
        setDashboardWidgetChoice();
    });
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
