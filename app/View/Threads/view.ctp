<div class="threads view">
    <h3><?php
        if (isset($thread['Thread']['event_id']) && $thread['Thread']['event_id']) {
            echo '<a href="' . $baseurl . '/events/view/' . h($thread['Thread']['event_id']) . '">' . h($thread['Thread']['title']) . '</a>';
        } else {
            echo h($thread['Thread']['title']);
        }
    ?></h3>
<?php
    echo $this->element('eventdiscussion');
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'threads', 'menuItem' => 'view'));
?>
