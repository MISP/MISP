<div class="events form">
<?php echo $this->Form->create('', array('type' => 'file'));?>
    <fieldset>
        <legend><?= h(Inflector::humanize($module['name'])) ?></legend>
        <?php if (isset($module['meta']['description'])) {
            echo '<p>' . h($module['meta']['description']) . '</p>';
        } ?>
        <?php
            if (isset($module['mispattributes']['userConfig']) && !empty($module['mispattributes']['userConfig'])) {
                foreach ($module['mispattributes']['userConfig'] as $configName => $config) {
                    $settings = array(
                        'label' => false,
                        'div' => false
                    );
                    if (isset($configTypes[$config['type']]['class'])) {
                        $settings['class'] = $configTypes[$config['type']]['class'];
                    }
                    if (isset($configTypes[$config['type']]['field'])) {
                        $settings['type'] = $configTypes[$config['type']]['field'];
                    }
                    switch($settings['type']) {
                        case 'select':
                            if (isset($config['options'])) {
                                $settings['options'] = $config['options'];
                            }
                            break;
                        case 'checkbox':
                            if (isset($config['checked'])) {
                                $settings['checked'] = $config['checked'];
                            }
                            break;
                    }
                    ?>
                    <span class="bold"><?= ucfirst(h($configName)) ?></span><br>
                    <?php
                        if ($settings['type'] === 'checkbox'):
                            echo $this->Form->input('Event.config.' . $configName, $settings);
                            if (isset($config['message']) && !empty($config['message'])):
                                echo ' ' . h($config['message']);
                    ?>
                                <br>
                    <?php
                            endif;
                        else:
                            if (isset($config['message']) && !empty($config['message'])):
                            ?>
                                <p><?= h($config['message']) ?></p>
                            <?php
                            endif;
                            echo $this->Form->input('Event.config.' . $configName, $settings);
                        endif;
                    ?>
                    <div class="input clear"></div><br>
                    <?php
                }
            }
            $source = 'paste';
            if (in_array('paste', $module['mispattributes']['inputSource']) && in_array('file', $module['mispattributes']['inputSource'])) {
                $source = 'both';
            } else if (in_array('file', $module['mispattributes']['inputSource'])) {
                $source = 'file';
            }
            if (!empty($module['mispattributes']['inputSource'])):
                echo $this->Form->input('Event.source', array(
                    'label' => false,
                    'checked' => $source === 'file' ? true : false,
                    'disabled' => $source === 'both' ? false : true,
                    'div' => false,
                    'style' => 'margin-bottom:5px;'
                ));
                ?>
                <span class="bold"><?= __('File upload') ?></span>
                    <div class="input clear"></div>
                    <div id="pasteDiv">
                    <p class="bold"><?= __('Paste Input') ?></p>
                <?php
                        if (in_array('paste', $module['mispattributes']['inputSource'])) {
                            echo $this->Form->input('Event.paste', array(
                                'label' => false,
                                'type' => 'textarea',
                                'class' => 'input-xxlarge',
                                'rows' => 12,
                                'div' => false
                            ));
                        }
                ?>
                    </div>
                    <div class="input clear"></div>
                    <div id="fileDiv">
                    <p class="bold"><?= __('Input File') ?></p>
                <?php
                        if (in_array('file', $module['mispattributes']['inputSource'])) {
                            echo $this->Form->input('Event.fileupload', array(
                                'label' => false,
                                'type' => 'file',
                                'div' => 'clear'
                            ));
                        }
                ?>
                    </div>
                    <div class="input clear"></div>
        <?php
            endif;
        ?>
    </fieldset>
<?php
echo $this->Form->button('Import', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>

<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'populateFrom', 'event' => $event)); ?>
<script type="text/javascript">
$(function() {
    changeImportSource();
    $('#EventSource').change(function() {
        changeImportSource();
    });
});

function changeImportSource() {
    if ($('#EventSource').is(':checked')) {
        $('#fileDiv').show();
        $('#pasteDiv').hide();
    } else {
        $('#fileDiv').hide();
        $('#pasteDiv').show();
    }
}
</script>
