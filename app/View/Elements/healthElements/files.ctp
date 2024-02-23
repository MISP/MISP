<?php
$humanReadableFilesize = function ($bytes, $dec = 2) {
    $size = ['B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    $factor = floor((strlen($bytes) - 1) / 3);
    return sprintf("%.{$dec}f&nbsp;%s", ($bytes / (1024 ** $factor)), $size[$factor]);
};
?>
<div style="border:1px solid #dddddd; margin-top:1px; width:100%; padding:10px">
    <p><?php echo __('Below you will find a list of the uploaded files based on type.');?></p>
    <?php
        foreach ($files as $k => $file):
    ?>
        <h3><?php echo h($file['name']); ?></h3>
        <div>
            <b><?php echo __('Description');?></b>: <?php echo $file['description']; ?><br>
            <b><?php echo __('Expected Format');?></b>: <?php echo h($file['valid_format']);?><br>
            <b><?php echo __('Path');?></b>:  <?php echo h($file['path']);?><br>
            <?php
                if (!empty($file['expected'])):
            ?>
                <b><?php echo __('Files set for each relevant setting');?>:</b><br>
                <ul>
                    <?php foreach ($file['expected'] as $expectedKey => $expectedValue):
                        $colour = 'red';
                        foreach ($file['files'] as $f) if ($f['filename'] == $expectedValue) $colour = 'green';
                    ?>
                        <li><b><?php echo h($expectedKey); ?></b>: <span style="color:<?php echo $colour; ?>"><?php echo h($expectedValue); ?></span></li>
                    <?php endforeach; ?>
                </ul>
            <?php
                endif;
            ?>
        </div>
        <table class="table table-striped table-hover table-condensed" style="width:700px">
            <tr>
                <th><?php echo __('Filename');?></th>
                <th><?php echo __('Used by');?></th>
                <th><?php echo __('Size');?></th>
                <th><?php echo __('Permissions');?></th>
                <th><?php echo __('Actions');?></th>
            </tr>
                <?php
                    foreach ($file['files'] as $f):
                        $permission = "";
                        if ($f['link']) $permission .= "l";
                        if ($f['read']) $permission .= "r";
                        if ($f['write']) $permission .= "w";
                        if ($f['execute']) $permission .= "x";
                    ?>
                    <tr>
                        <td><?php echo h($f['filename']);?></td>
                        <td width="150px;">
                            <?php
                                if ($k != 'orgs'):
                                    foreach ($file['expected'] as $ek => $ev):
                                        if ($f['filename'] == $ev) echo h($ek) . "<br>";
                                    endforeach;
                                else:
                                    echo __('N/A');
                                endif;
                            ?>
                        </td>
                        <td width="75px;">
                            <?= $humanReadableFilesize($f['filesize'], 1) ?>
                        </td>
                        <td class="short">
                            <?php echo $permission;?>
                        </td>
                        <td class="short">
                            <?php
                                echo $this->Form->postLink('', array('controller' => 'servers', 'action' => 'deleteFile' , $k , $f['filename']), array('class' => 'fa fa-trash', 'title' => __('Delete')), __('Are you sure you want to delete %s?', $f['filename']));
                            ?>
                        </td>
                    </tr>
                <?php
                    endforeach;
                ?>
            </table>
    <?php
            echo $this->Form->create('Server', array('type' => 'file', 'url' => $baseurl . '/servers/uploadFile/' . $k));?>
                <fieldset>
                    <?php
                    echo $this->Form->hidden('event_id');
                    echo $this->Form->file('file', array(
                        'error' => array('escape' => false),
                    ));
                    ?>
                </fieldset>
            <?php
            echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
            echo $this->Form->end();
        endforeach;
    ?>
</div>
