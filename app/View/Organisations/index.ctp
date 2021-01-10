<div class="organisations index">
<?php
    $texts = array(
            'all' => array(
                    'text' => __('All organisations'),
                    'extra' => __(', both local and remote')
            ),
            'external' => array(
                    'text' => __('Known remote organisations'),
                    'extra' => __(' on other instances')
            ),
            'local' => array(
                    'text' => __('Local organisations'),
                    'extra' => __(' having a presence on this instance')
            ),
    );
    if (!in_array($scope, array_keys($texts))) $scope = 'local';
    $partial = array();
    foreach($named as $key => $value):
        if ($key == 'page' || $key == 'viewall'):
            continue;
        endif;
        $partial[] = h($key) . ':' . h($value);
    endforeach;
    $viewall_button_text = __('Paginate');
    if (!$viewall):
        $viewall_button_text = __('View all');
        $partial[] = 'viewall:1';
    endif;
?>
    <h2><?php echo $texts[$scope]['text'] . $texts[$scope]['extra']; ?></h2>
    <div class="pagination">
        <ul>
            <?php
                echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
                echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
                echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            ?>
            <li class="all">
                <a href="<?php echo $baseurl . '/organisations/index/' . implode('/', $partial); ?>"><?php echo $viewall_button_text; ?></a>
            </li>
        </ul>
    </div>
    <?php
        $data = array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'text' => __('Local organisations'),
                            'active' => $scope === 'local',
                            'url' => $baseurl . '/organisations/index/scope:local'
                        ),
                        array(
                            'text' => __('Known remote organisations'),
                            'active' => $scope === 'external',
                            'url' => $baseurl . '/organisations/index/scope:external'
                        ),
                        array(
                            'text' => __('All organisations'),
                            'active' => $scope === 'all',
                            'url' => $baseurl . '/organisations/index/scope:all'
                        ),
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
            <th><?php echo $this->Paginator->sort('id');?></th>
            <th><?php echo __('Logo');?></th>
            <th><?php echo $this->Paginator->sort('name');?></th>
            <?php if ($isSiteAdmin): ?>
                <th><?php echo $this->Paginator->sort('uuid', 'UUID');?></th>
            <?php endif; ?>
            <th><?php echo $this->Paginator->sort('description');?></th>
            <th><?php echo $this->Paginator->sort('nationality');?></th>
            <th><?php echo $this->Paginator->sort('sector');?></th>
            <th><?php echo $this->Paginator->sort('type');?></th>
            <th><?php echo $this->Paginator->sort('contacts');?></th>
            <?php if ($isSiteAdmin): ?>
                <th><?php echo __('Added by');?></th>
            <?php endif; ?>
            <th><?php echo $this->Paginator->sort('local');?></th>
            <th><?= $this->Paginator->sort('user_count', __('Users'));?></th>
            <th><?php echo $this->Paginator->sort('restrictions');?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr>
    <?php
foreach ($orgs as $org): ?>
    <tr>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'"><?php echo h($org['Organisation']['id']); ?></td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'">
            <?= $this->OrgImg->getOrgLogo($org, 24) ?>
        </td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'"><?php echo h($org['Organisation']['name']); ?></td>
        <?php if ($isSiteAdmin): ?>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'">
            <span class="quickSelect"><?php echo h($org['Organisation']['uuid']); ?></span>
        </td>
        <?php endif; ?>
        <td ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'"><?php echo h($org['Organisation']['description']); ?></td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'"><?php
            if (isset($org['Organisation']['country_code'])) {
                echo $this->Icon->countryFlag($org['Organisation']['country_code']) . '&nbsp;';
            }
            if ($org['Organisation']['nationality'] !== 'Not specified') {
                echo h($org['Organisation']['nationality']);
            }
        ?></td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'"><?php echo h($org['Organisation']['sector']); ?></td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'"><?php echo h($org['Organisation']['type']); ?></td>
        <td><?php echo h($org['Organisation']['contacts']); ?></td>
        <?php if ($isSiteAdmin): ?>
            <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'">
                <?php echo (isset($org['Organisation']['created_by_email'])) ? h($org['Organisation']['created_by_email']) : '&nbsp;'; ?>
            </td>
        <?php endif; ?>
        <td class="short <?php echo $org['Organisation']['local'] ? 'green' : 'red';?>" ondblclick="document.location.href ='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id'];?>'"><?php echo $org['Organisation']['local'] ? __('Yes') : __('No');?></td>
        <td class="short"><?php echo isset($org['Organisation']['user_count']) ? $org['Organisation']['user_count'] : '0';?></td>
        <td class="short">
            <?php
                if (!empty($org['Organisation']['restricted_to_domain'])) {
                    echo implode('<br />', h($org['Organisation']['restricted_to_domain']));
                }
            ?>
        </td>
        <td class="short action-links">
            <?php if ($isSiteAdmin): ?>
                <a href='<?php echo $baseurl . "/admin/organisations/edit/" . $org['Organisation']['id'];?>' class = "fa fa-edit" title = "<?php echo __('Edit');?>" aria-label = "<?php echo __('Edit');?>"></a>
                <?php
                    echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $org['Organisation']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), __('Are you sure you want to delete %s?', $org['Organisation']['name']));
                ?>
            <?php endif; ?>
            <a href='<?php echo $baseurl . "/organisations/view/" . $org['Organisation']['id']; ?>' class = "fa fa-eye" title = "<?php echo __('View');?>" aria-label = "<?php echo __('View');?>"></a>
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
            <li class="all">
                <a href="<?php echo $baseurl . '/organisations/index/' . implode('/', $partial); ?>"><?php echo $viewall_button_text; ?></a>
            </li>
        </ul>
    </div>

</div>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(document).ready(function() {
        $('.searchFilterButton').click(function() {
            runIndexFilter(this);
        });
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter('/scope:<?php echo h($scope); ?>');
        });
    });
</script>
<?php
    if ($isSiteAdmin) echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'indexOrg'));
    else echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'indexOrg'));
