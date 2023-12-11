<?php
    echo $this->Form->create('UserSetting');
    echo $this->Form->input('path');
    echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();