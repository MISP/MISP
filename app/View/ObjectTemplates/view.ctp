<?php
    echo $this->element('side_menu', array('menuList' => 'objectTemplates', 'menuItem' => 'view'));
?>
<div class="object_template view">
    <div class="row-fluid">
        <div class="span8">
            <h2><?php echo h(ucfirst($template['ObjectTemplate']['name'])); ?><?php echo __(' Object Template');?></h2>
            <dl>
                <dt><?php echo __('Object Template ID');?></dt>
                <dd><?php echo h($template['ObjectTemplate']['id']); ?></dd>
                <dt><?php echo __('Name');?></dt>
                <dd><?php echo $template['ObjectTemplate']['name'] ? h($template['ObjectTemplate']['name']) : h($template['ObjectTemplate']['type']); ?></dd>
                <dt><?php echo __('Organisation');?></dt>
                <dd><?php echo h($template['Organisation']['name']); ?></dd>
                <dt><?php echo __('Uuid');?></dt>
                <dd><?php echo h($template['ObjectTemplate']['uuid']); ?></dd>
                <dt><?php echo __('Version');?></dt>
                <dd><?php echo h($template['ObjectTemplate']['version']); ?></dd>
                <dt><?php echo __('Meta-category');?></dt>
                <dd><?php echo h($template['ObjectTemplate']['meta-category']); ?></dd>
                <dt><?php echo __('Description');?></dt>
                <dd><?php echo h($template['ObjectTemplate']['description']); ?></dd>
                <dt><?php echo __('Requirements');?></dt>
                <dd>
                    <?php
                        if (!empty($template['ObjectTemplate']['requirements'])):
                            foreach ($template['ObjectTemplate']['requirements'] as $group => $requirements):
                    ?>
                                <span class="bold"><?php echo h($group); ?></span><br />
                    <?php
                                    foreach ($requirements as $requirement):
                    ?>
                                        <span>&nbsp;&nbsp;<?php echo h($requirement); ?></span><br />
                    <?php
                                    endforeach;
                            endforeach;
                        endif;
                    ?>
                </dd>
            </dl>
        </div>
    </div>
    <div id="ajaxContent" style="width:100%;"></div>
</div>
<script type="text/javascript">
<?php
    $startingTab = 'all';
?>
$(document).ready(function () {
    objectTemplateViewContent('<?php echo $startingTab; ?>', '<?php echo h($id);?>');
});
</script>
