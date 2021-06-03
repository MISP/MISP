<div class="jobs index">
    <h2><?php echo __('Jobs');?></h2>
    <h4><?php echo __('Purge job entries:');?></h4>
    <span>
        <?php
            echo $this->Form->postLink(
                __('Completed'),
                array('controller' => 'jobs', 'action' => 'clearJobs'),
                array('class' => 'btn btn-inverse qet toggle-left'),
                __('Are you sure you want to purge all completed job entries? Job entries are considered as log entries and have no impact on actual job execution.')
            );
            echo $this->Form->postLink(
                __('All'),
                array('controller' => 'jobs', 'action' => 'clearJobs', 'all'),
                array('class' => 'btn btn-inverse qet toggle-right'),
                __('Are you sure you want to purge all job entries? Job entries are considered as log entries and have no impact on actual job execution.')
            );
        ?>
    </span>
    <br />
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
    <script type="text/javascript">
        var intervalArray = [];

        function queueInterval(k, id) {
            intervalArray[k] = setInterval(function() {
                if (!document.hidden) {
                    $.getJSON('<?php echo $baseurl; ?>/jobs/getGenerateCorrelationProgress/' + id, function(data) {
                        var x = document.getElementById("bar" + id);
                        if (data.progress == 0) {
                            x.innerText = data.job_status;
                        } else if (data.progress > 0 && data.progress < 100) {
                            x.style.width = data.progress + "%";
                            x.innerText = data.progress + "%";
                        } else if (data.progress == 100) {
                            x.style.width = "100%";
                            x.innerText = "<?php echo __('Completed.');?>";
                            x.parentElement.className = "progress";
                            clearInterval(intervalArray[k]);
                        }
                    });
                }
            }, 3000);
        }
    </script>
    <?php
        $data = array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'url' => $baseurl . '/jobs/index',
                            'text' => __('All'),
                            'title' => __('Show all queues'),
                            'active' => !$queue
                        ),
                        array(
                            'url' => $baseurl . '/jobs/index/default',
                            'text' => __('Default'),
                            'title' => __('Show default queue'),
                            'active' => $queue === 'default'
                        ),
                        array(
                            'url' => $baseurl . '/jobs/index/prio',
                            'text' => __('Prio'),
                            'title' => __('Show prio queue'),
                            'active' => $queue === 'prio'
                        ),
                        array(
                            'url' => $baseurl . '/jobs/index/email',
                            'text' => __('Email'),
                            'titles' => __('Show email queue'),
                            'active' => $queue === 'email'
                        ),
                        array(
                            'url' => $baseurl . '/jobs/index/cache',
                            'text' => __('Cache'),
                            'title' => __('Show cache queue'),
                            'active' => $queue === 'cache'
                        )
                    )
                )
            )
        );
    ?>
    <div>
        <?php echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data)); ?>
        <table class="table table-striped table-hover table-condensed">
        <tr>
            <th><?php echo $this->Paginator->sort('id', __('ID'));?></th>
            <th><?php echo $this->Paginator->sort('date_created', __('Date created'));?></th>
            <th><?php echo $this->Paginator->sort('date_modified', __('Date modified'));?></th>
            <th><?php echo $this->Paginator->sort('process_id', __('Process ID'));?></th>
            <th><?php echo $this->Paginator->sort('worker', __('Worker'));?></th>
            <th><?php echo $this->Paginator->sort('job_type', __('Job type'));?></th>
            <th><?php echo $this->Paginator->sort('job_input', __('Input'));?></th>
            <th><?php echo $this->Paginator->sort('message');?></th>
            <th><?php echo $this->Paginator->sort('Org.name', __('Organisation name'));?></th>
            <th><?php echo $this->Paginator->sort('status');?></th>
            <th><?php echo $this->Paginator->sort('progress');?></th>
        </tr>
<?php
    foreach ($list as $k => $item):
        $progress = '100';
        $startRefreshing = false;
        if ($item['Job']['failed'] || $item['Job']['status'] == Job::STATUS_FAILED) {
            $item['Job']['job_status'] = 'Failed';
            $progress_message = __('Failed');
            $progress_bar_type = 'progress progress-danger active';
        } else if (!$item['Job']['worker_status'] && $item['Job']['progress'] != 100) {
            $progress_message = __('No worker active');
            $progress_bar_type = 'progress progress-striped progress-warning active';
        } else if ($item['Job']['progress'] == 0) {
            $progress_bar_type = 'progress progress-striped progress-queued active';
            $progress_message = $item['Job']['job_status'] === 'Running' ? __('Running') : __('Queued');
            $startRefreshing = true;
        } else {
            $progress = h($item['Job']['progress']);
            if ($item['Job']['progress'] == 100) {
                $progress_bar_type = 'progress';
                $progress_message = __('Completed');
            } else {
                $progress_bar_type = 'progress progress-striped';
                $progress_message = $item['Job']['progress'] . '%';
                $startRefreshing = true;
            }
        }
?>
        <tr>
            <td class="short"><?php echo h($item['Job']['id']); ?></td>
            <td class="short"><?= $this->Time->time($item['Job']['date_created']) ?></td>
            <td class="short"><?= $this->Time->time($item['Job']['date_modified']) ?></td>
            <td class="short"><?php echo h($item['Job']['process_id']); ?></td>
            <td class="short"><?php echo h($item['Job']['worker']); ?></td>
            <td class="short"><?php echo h($item['Job']['job_type']); ?></td>
            <td class="short"><?php echo h($item['Job']['job_input']); ?></td>
            <td><?php echo h($item['Job']['message']); ?></td>
            <td class="short"><?php echo isset($item['Org']['name']) ? h($item['Org']['name']) : 'SYSTEM'; ?></td>
            <td class="short">
            <?php
                echo h($item['Job']['job_status']);
                if ($item['Job']['failed']):
            ?>
                <div class="fa fa-search useCursorPointer queryPopover" title="<?php echo __('View stacktrace');?>" role="button" tabindex="0" aria-label="<?php echo __('View stacktrace');?>" data-url="<?php echo $baseurl; ?>/jobs/getError" data-id="<?php echo h($item['Job']['process_id']); ?>"></div>
            <?php
                endif;
            ?>
            </td>
            <td style="width:200px;">
                <div class="<?php echo $progress_bar_type; ?>" style="margin-bottom: 0px;">
                  <div id="bar<?php echo h($item['Job']['id']); ?>" class="bar" style="width: <?php echo $progress; ?>%;">
                    <?= h($progress_message); ?>
                  </div>
                </div>
                    <?php
                        if ($startRefreshing):
                    ?>
                            <script type="text/javascript">
                                queueInterval("<?php echo $k; ?>", "<?php echo h($item['Job']['id']); ?>");
                            </script>
                    <?php
                        endif;
                    ?>
            </td>
        </tr><?php
    endforeach; ?>
        </table>
    </div>
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
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'jobs'));
