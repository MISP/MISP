<div class="objectTemplates index">
    <h2><?php echo __('Object Template index');?></h2>
    <div class="pagination">
        <ul>
            <?php
                $this->Paginator->options(array(
                        'update' => '.span12',
                        'evalScripts' => true,
                        'before' => '$(".progress").show()',
                        'complete' => '$(".progress").hide()',
                ));

                echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
                echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
                echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            ?>
        </ul>
    </div>
    <div id="hiddenFormDiv">
    <?php
        if ($isSiteAdmin) {
            echo $this->Form->create('ObjectTemplate', array('url' => '/ObjectTemplates/activate'));
            echo $this->Form->input('data', array('label' => false, 'style' => 'display:none;'));
            echo $this->Form->end();
        }
    ?>
    </div>
    <div class="tabMenuFixedContainer" style="display:inline-block;">
        <?php
            if ($isSiteAdmin):
        ?>
                <span role="button" tabindex="0" aria-label="<?php echo __('Enabled');?>" title="<?php echo __('Enabled');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer <?php if (!$all) echo 'tabMenuActive';?>" onClick="window.location='/objectTemplates/index'"><?php echo __('Enabled');?></span>
                <span role="button" tabindex="0" aria-label="<?php echo __('All');?>" title="<?php echo __('All');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer <?php if ($all) echo 'tabMenuActive';?>" onClick="window.location='/objectTemplates/index/all'"><?php echo __('All');?></span>
        <?php
            endif;
        ?>
    </div>
    <table class="table table-striped table-hover table-condensed">
    <tr>
            <?php
                if ($isSiteAdmin):
            ?>
                    <th><?php echo $this->Paginator->sort('active');?></th>
            <?php
                endif;
            ?>
            <th><?php echo $this->Paginator->sort('id');?></th>
            <th><?php echo $this->Paginator->sort('name');?></th>
            <th><?php echo $this->Paginator->sort('uuid');?></th>
            <th><?php echo $this->Paginator->sort('org_id', __('Organisation'));?></th>
            <th><?php echo $this->Paginator->sort('version');?></th>
            <th><?php echo $this->Paginator->sort('meta-category');?></th>
            <th><?php echo $this->Paginator->sort('description');?></th>
            <th><?php echo __('Requirements');?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr>
    <?php
foreach ($list as $template):
    $td_attributes = 'ondblclick="document.location.href =\'/objectTemplates/view/' . h($template['ObjectTemplate']['id']) . '\'"';
    ?>
    <tr>
        <?php
            if ($isSiteAdmin):
        ?>
                <td class="short" <?php echo $td_attributes; ?>>
                    <input id="checkBox_<?php echo h($template['ObjectTemplate']['id']); ?>" type="checkbox" onClick="toggleSetting(event, 'activate_object_template', '<?php echo h($template['ObjectTemplate']['id']); ?>')" <?php echo $template['ObjectTemplate']['active'] ? 'checked' : ''; ?>/>
                </td>
        <?php
            endif;
        ?>
        <td class="short" <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['id']); ?></td>
        <td class="shortish" <?php echo $td_attributes; ?>>
            <?php
                if ($template['ObjectTemplate']['fixed']):
            ?>
                <img src="<?php echo $baseurl;?>/img/orgs/MISP.png" width="24" height="24" style="padding-bottom:3px;" />
            <?php
                endif;
            ?>
                    <span class="bold"><?php echo h($template['ObjectTemplate']['name']); ?></span>
        </td>
        <td class="short" <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['uuid']); ?></td>
        <td class="short" <?php echo $td_attributes; ?>><?php echo h($template['Organisation']['name']); ?></td>
        <td class="short" <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['version']); ?></td>
        <td class="short" <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['meta-category']); ?></td>
        <td <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['description']); ?></td>
        <td <?php echo $td_attributes; ?>>
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
        </td>
        <td class="short action-links">
            <a href='/objectTemplates/view/<?php echo $template['ObjectTemplate']['id']; ?>' class = "icon-list-alt" title = "<?php echo __('View');?>"></a>
            <?php
                if ($isSiteAdmin):
                    echo $this->Form->postLink('', array('action' => 'update', $template['ObjectTemplate']['name'], 1), array('class' => 'icon-refresh', 'title' => 'Force update'), __('Are you sure you want to force an update for template # %s?', $template['ObjectTemplate']['id']));
                    echo $this->Form->postLink('', array('action' => 'delete', $template['ObjectTemplate']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete template # %s?', $template['ObjectTemplate']['id']));
                endif;
            ?>
        </td>
    </tr>
    <?php
endforeach; ?>
    </table>
    <p>
    <?php
    echo $this->Paginator->counter(array(
    'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
    ));
    ?>
    </p>
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'objectTemplates', 'menuItem' => 'index'));
