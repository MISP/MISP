<div class="templates view">
<h2><?php  echo __('Template');?></h2>
    <dl>
        <dt><?php echo __('Id'); ?></dt>
        <dd>
            <?php echo h($template['Template']['id']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Name'); ?></dt>
        <dd>
            <?php echo h($template['Template']['name']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Description'); ?></dt>
        <dd>
            <?php echo h($template['Template']['description']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Tags'); ?></dt>
        <dd>
            <table>
                <tr id = "tags">
                    <?php
                        if (!empty($template['TemplateTag'])) {
                            foreach ($template['TemplateTag'] as $tag) {
                                echo $this->element('ajaxTemplateTag', array('tag' => $tag, 'editable' => 'no'));
                            }
                        } else echo '&nbsp';
                    ?>
                </tr>
            </table>
        </dd>
        <dt><?php echo __('Organisation'); ?></dt>
        <dd>
            <?php echo h($template['Template']['org']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Shareable'); ?></dt>
        <dd>
            <?php
                if ($template['Template']['share']) echo __('Yes');
                else echo __('No');
            ?>
        </dd>
    </dl>
    <div id="templateElements">
    </div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'templates', 'menuItem' => 'view', 'mayModify' => $mayModify));
?>
<script type="text/javascript">
$(document).ready( function () {
    updateIndex(<?php echo $template['Template']['id']?>, 'template');
});
</script>
