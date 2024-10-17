<div class="objectTemplates index">
    <h2><?php echo __('Object Template index');?></h2>
    <div class="pagination">
        <ul>
            <?php
                echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
                echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
                echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            ?>
        </ul>
    </div>
    <div id="hiddenFormDiv">
    <?php
        if ($isSiteAdmin) {
            echo $this->Form->create('ObjectTemplate', array('url' => $baseurl . '/ObjectTemplates/activate'));
            echo $this->Form->input('data', array('label' => false, 'style' => 'display:none;'));
            echo $this->Form->end();
        }
    ?>
    </div>
    <?php
        $data = array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'url' => $baseurl . '/objectTemplates/index',
                            'text' => __('Enabled'),
                            'active' => !$all
                        ),
                        array(
                            'url' => $baseurl . '/objectTemplates/index/all',
                            'text' => __('All'),
                            'active' => $all
                        )
                    )
                ),
                array(
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                )
            )
        );
        echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data));
    ?>
    <table class="table table-striped table-hover table-condensed">
    <tr>
            <?php
                if ($isSiteAdmin):
            ?>
                    <th><?php echo $this->Paginator->sort('active', __('Active'));?></th>
            <?php
                endif;
            ?>
            <th><?php echo $this->Paginator->sort('id');?></th>
            <th><?php echo $this->Paginator->sort('name');?></th>
            <th><?php echo $this->Paginator->sort('uuid', __('UUID'));?></th>
            <th><?php echo $this->Paginator->sort('org_id', __('Organisation'));?></th>
            <th><?php echo $this->Paginator->sort('version');?></th>
            <th><?php echo $this->Paginator->sort('meta-category', __('Meta-category'));?></th>
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
                    <?php echo '<img src="' . $this->Image->base64(APP . 'files/img/orgs/MISP.png') . '" alt="' . __('MISP logo') . '" width="24" height="24" style="padding-bottom:3px" onerror="this.style.display=\'none\';">';?>
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
            <a href='<?php echo $baseurl; ?>/objectTemplates/view/<?php echo $template['ObjectTemplate']['id']; ?>' class = "fa fa-eye" title = "<?php echo __('View');?>" aria-label = "<?php echo __('View');?>"></a>
            <?php
                if ($isSiteAdmin):
                    echo $this->Form->postLink('', array('action' => 'update', $template['ObjectTemplate']['name'], 1), array('class' => 'fa fa-sync', 'title' => __('Force update')), __('Are you sure you want to force an update for template # %s?', $template['ObjectTemplate']['id']));
                    echo $this->Form->postLink('', array('action' => 'delete', $template['ObjectTemplate']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete')), __('Are you sure you want to delete template # %s?', $template['ObjectTemplate']['id']));
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
<script type="text/javascript">
    $(document).ready(function(){
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'objectTemplates', 'menuItem' => 'index'));
