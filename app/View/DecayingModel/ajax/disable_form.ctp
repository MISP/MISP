<div>
    <?php
        echo $this->Form->create('DecayingModel', array('url' => '/DecayingModel/disable/' . $model['id']));
        echo $this->Form->end();
    ?>
</div>
