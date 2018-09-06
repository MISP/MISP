<div class="templates view">
<h2><?php echo __('News');?></h2>
    <div>
        <?php
            if (!empty($newsItems)):
                foreach ($newsItems as $newsItem): ?>
                    <div class="templateTableRow" style="width:800px;">
                        <div class="templateElementHeader" style="width:100%;position:relative;<?php if ($newsItem['News']['new']) echo 'background-color:red;'?>">
                            <div class="templateGlass"></div>
                            <div class ="templateElementHeaderText" style="width:100%;">
                                <div style="float:left;width:83%;"><?php echo $newsItem['User']['email'] ? h($newsItem['User']['email']) : 'Administrator'; ?></div>
                                <div style="float:left;width:17%;"><?php echo date('Y/m/d H:i:s', $newsItem['News']['date_created']); ?></div>
                            </div>
                        </div>
                        <div style="padding:6px;">
                            <h4><?php echo h($newsItem['News']['title']);?></h4>
                            <?php
                                $message = h($newsItem['News']['message']);
                                echo nl2br(preg_replace('#https?:\/\/[^\s]*#i', '<a href="$0">$0</a>', $message));
                                if ($isSiteAdmin):
                            ?>
                                    <br /><a href="<?php echo $baseurl; ?>/news/edit/<?php echo h($newsItem['News']['id']);?>" class="icon-edit" title="<?php echo __('Edit news message');?>"></a>
                            <?php
                                    echo $this->Form->postLink('', array('action' => 'delete', $newsItem['News']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete news item # %s?', $newsItem['News']['id']));
                                endif;
                            ?>
                        </div>
                    </div>
                    <br />
        <?php
                endforeach;
                echo $this->Paginator->counter(array(
                        'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
                ));
        ?>
            <div class="pagination">
                <ul>
                <?php
                    echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
                    echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
                    echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
                ?>
                </ul>
            </div>
        <?php
            else:
                echo __('There are currently no news messages.');
            endif;
        ?>
    </div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'news', 'menuItem' => 'index'));
?>
