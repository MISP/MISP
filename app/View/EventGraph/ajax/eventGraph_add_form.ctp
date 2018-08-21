<?php
    $url_params = $action == 'add' ? 'add/' . $event_id : 'edit/' . $eventGraph['id'];
    echo $this->Form->create('EventGraph', array('url' => '/EventGraph/' . $url_params));
?>
    <fieldset>
        <legend><?php echo $action == 'add' ? __('Add EventGraph') : __('Edit EventGraph'); ?></legend>
        <div class="add_eventgraph_fields">
            <?php
            echo $this->Form->hidden('event_id');
            echo $this->Form->input('network_name', array(
                'type' => 'text'
            ));
            echo $this->Form->input('network_json', array(
                'type' => 'textarea'
            ));
            echo $this->Form->input('preview_img', array(
                'type' => 'textarea'
            ));

            echo $this->Form->button($action);
            echo $this->Form->end();
        ?>
        </div>
    </fieldset>
