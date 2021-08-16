<div class="warninglist view">
    <h2><?= __('Search in enabled Warninglists') ?></h2>
    <?php
        echo $this->Form->create('Warninglist');
        echo sprintf('<div class="input-append">%s%s</div>',
            $this->Form->input('', array(
                'label' => false,
                'div' => false,
                'type' => 'text',
                'class' => 'input-xlarge',
            )),
            $this->Form->button(__('Search'), array('class' => 'btn btn-primary', 'placeholder' => __('Enter a value to search for')))
        );
        echo $this->Form->end();
    ?>

    <?php if(!empty($hits)): ?>
        <?php foreach ($hits as $value => $lists): ?>
            <?= __('Result for <i>%s</i>:', h($value))?>
            <ul>
                <?php foreach ($lists as $list): ?>
                    <li><a href="<?= $baseurl . '/warninglists/view/' . h($list['id']) ?>"><?= h($list['name']) ?></a></li>
                <?php endforeach; ?>
            </ul>
        <?php endforeach; ?>
    <?php elseif (!empty($data)): ?>
        <?= __('No hits for: <i>%s</i>', h($data)) ?>
    <?php endif; ?>
</div>

<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'warninglist', 'menuItem' => 'check_value')); ?>
