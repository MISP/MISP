<div class='form'>
    <?php if(!$newVersionAvailable): ?>
        <div class="alert alert-warning"><?= __('No new version available') ?></div>
    <?php else: ?>
        <div class="alert alert-success">
            <div><?= sprintf(__('Current fork version: %s'), h($forkVersion)) ?></div>
            <div><?= sprintf(__('New version available: %s'), sprintf('<strong>%s</strong>', h($parentVersion))) ?></div>
        </div>

        <div class="row" style="max-height: 500px;">
            <div class="span6">
                <h4><?= __('Parent fork') ?></h4>
                <table class="table table-striped table-hover table-condensed">
                    <thead>
                        <tr>
                            <th><?= __('Key'); ?></th>
                            <th><?= __('Value'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($parentElements)): ?>
                            <tr>
                                <td colspan="2"><?= __('No cluster element') ?></td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($parentElements as $k => $element): ?>
                                <tr>
                                    <td><?= h($element['key']) ?></td>
                                    <td><?= h($element['value']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <div class="span6">
                <h4><?= __('Current cluster') ?></h4>
                <table class="table table-striped table-hover table-condensed">
                    <thead>
                        <tr>
                            <th><?= __('Key'); ?></th>
                            <th><?= __('Value'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($clusterElements)): ?>
                            <tr>
                                <td colspan="2"><?= __('No cluster element') ?></td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($clusterElements as $k => $element): ?>
                                <tr>
                                    <td><?= h($element['key']) ?></td>
                                    <td><?= h($element['value']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <h4><?= __('Cluster Elements in original fork but not in this cluster') ?></h4>
        <?php echo $this->Form->create('GalaxyCluster');?>
        <div class="row">
            <div class="span8">
                <table class="table table-striped table-hover table-condensed">
                    <thead>
                        <tr>
                            <th><?= __('Key'); ?></th>
                            <th><?= __('Value'); ?></th>
                            <th><?= __('Import element into the cluster') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($missingElements as $k => $element): ?>
                            <tr>
                                <td><?= h($element['key']) ?></td>
                                <td><?= h($element['value']) ?></td>
                                <td>
                                    <?php
                                        echo $this->Form->input('element-'.$k, array(
                                            'label' => __('Import'),
                                            'type' => 'checkbox',
                                            'checked' => true
                                        ));
                                    ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
            echo $this->Form->button(__('Update'), array('class' => 'btn btn-primary'));
            echo $this->Form->end();
        ?>
    <?php endif; ?>
</div>

<?php echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'update_cluster')); ?>
</div>