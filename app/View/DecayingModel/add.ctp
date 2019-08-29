<div class="form">
<?php echo $this->Form->create('DecayingModel');?>
    <fieldset>
        <legend><?php echo Inflector::humanize($action) . __(' Decaying Model');?></legend>
    <?php
        if (isset($restrictEdition) && $restrictEdition) {
            echo '<div class="alert alert-warning">' . __('You are editing a Default Model, only restricted edition is allowed.') . '</div>';
            echo $this->Form->input('all_orgs', array(
                'label' => __('Can other organization use this model'),
                'type' => 'checkbox',
                'checked' => isset($this->request->data['DecayingModel']['all_orgs']) ? $this->request->data['DecayingModel']['all_orgs'] : true
            ));
            echo $this->Form->input('enabled', array(
                'type' => 'checkbox'
            ));
        } else {
            echo $this->Form->input('name', array(
                'type' => 'text'
            ));
            echo $this->Form->input('description', array(
            ));
            echo $this->Form->input('formula', array(
                'value' => isset($this->request->data['DecayingModel']['formula']) ? $this->request->data['DecayingModel']['formula'] : 'polynomial',
                'options' => $available_formulas,
                'div' => 'clear'
            ));
            echo $this->Form->input('all_orgs', array(
                'label' => __('Can other organization use this model'),
                'type' => 'checkbox',
                'checked' => isset($this->request->data['DecayingModel']['all_orgs']) ? $this->request->data['DecayingModel']['all_orgs'] : true
            ));
            echo $this->Form->input('enabled', array(
                'type' => 'checkbox'
            ));
            echo '<div id="ContainerPolynomialSetting">';
            echo $this->Form->input('DecayingModel.parameters.lifetime', array(
                'label' => __('Lifetime parameter'),
                'type' => 'number',
                'min' => 0,
                'title' => _('The end of life of the indicator'),
                'class' => 'form-control span6',
                'div' => 'input clear',
                'value' => isset($this->request->data['DecayingModel']['parameters']['lifetime']) ? $this->request->data['DecayingModel']['parameters']['lifetime'] : ''
            ));
            echo $this->Form->input('DecayingModel.parameters.decay_speed', array(
                'label' => __('Decay speed parameter'),
                'type' => 'number',
                'min' => 0,
                'step' => 0.01,
                'title' => _('The decay speed of the indicator'),
                'class' => 'form-control span6',
                'div' => 'input clear',
                'value' => isset($this->request->data['DecayingModel']['parameters']['decay_speed']) ? $this->request->data['DecayingModel']['parameters']['decay_speed'] : ''
            ));
            echo $this->Form->input('DecayingModel.parameters.threshold', array(
                'label' => __('Threshold parameter'),
                'type' => 'number',
                'min' => 0,
                'title' => _('The model threshold of the indicator'),
                'class' => 'form-control span6',
                'div' => 'input clear',
                'value' => isset($this->request->data['DecayingModel']['parameters']['threshold']) ? $this->request->data['DecayingModel']['parameters']['threshold'] : ''
            ));
            echo $this->Form->input('DecayingModel.parameters.default_base_score', array(
                'label' => __('Default base_score parameter'),
                'type' => 'number',
                'min' => 0,
                'title' => _('The model default base_score of the indicator'),
                'class' => 'form-control span6',
                'div' => 'input clear',
                'value' => isset($this->request->data['DecayingModel']['parameters']['default_base_score']) ? $this->request->data['DecayingModel']['parameters']['default_base_score'] : ''
            ));
            echo '<div class="clear"></div>';
            echo '<label for="DecayingModelParametersBaseScoreConfig">' . __('Base Score configuration') . '</label>';
            echo $this->Form->textarea('DecayingModel.parameters.base_score_config', array(
                'class' => 'form-control span6',
                'cols' => '10',
                'value' => isset($this->request->data['DecayingModel']['parameters']['base_score_config']) ? json_encode($this->request->data['DecayingModel']['parameters']['base_score_config']) : ''
            ));
            echo '</div>';
            echo '<div id="ContainerOtherSetting">';
                echo '<div class="clear"></div>';
                echo '<label for="DecayingModelOtherSettings">' . __('Model Settings') . '</label>';
                echo $this->Form->textarea('DecayingModel.parameters.settings', array(
                    'class' => 'form-control span6',
                    'cols' => '10',
                    'value' => isset($this->request->data['DecayingModel']['parameters']['settings']) ? json_encode($this->request->data['DecayingModel']['parameters']['settings']) : ''
                ));
            echo '</div>';
        }
    ?>
        <div class="clear"></div>
    </fieldset>
<?php
    echo $this->Form->button(Inflector::humanize($action), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'add'));
?>
<script>
    toggleOtherSetting();
    $(document).ready(function() {
        $('#DecayingModelFormula').on('input', function() {
            toggleOtherSetting();
        })
    });
    function toggleOtherSetting() {
        if ($('#DecayingModelFormula').val() === 'Polynomial') {
            $('#ContainerOtherSetting').hide();
        } else {
            $('#ContainerOtherSetting').show();
        }
    }
</script>
