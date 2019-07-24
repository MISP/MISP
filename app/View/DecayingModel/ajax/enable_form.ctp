<div>
    <?php
        echo $this->Form->create('DecayingModel', array('url' => '/DecayingModel/enable/' . $model['id']));
        echo $this->Form->end();
    ?>
</div>
