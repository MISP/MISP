<div class="event index">
    <h2><?php echo __('Export');?></h2>
    <p><?php echo __('Export functionality is designed to automatically generate signatures for intrusion detection systems. To enable signature generation for a given attribute, Signature field of this attribute must be set to Yes.
        Note that not all attribute types are applicable for signature generation, currently we only support NIDS signature generation for IP, domains, host names, user agents etc., and hash list generation for MD5/SHA1 values of file artifacts. Support for more attribute types is planned.');?>
    <br/>
    <p><?php echo __('Simply click on any of the following buttons to download the appropriate data.');?></p>
    <?php $i = 0;?>
    <script type="text/javascript">
        var jobsArray = new Array();
        var intervalArray = new Array();
        function queueInterval(i, k, id, progress, modified) {
            jobsArray[i] = id;
            intervalArray[i] = setInterval(function(){
                    if (id != -1 && progress < 100 && modified != "N/A") {
                        queryTask(k, i);
                    }
                }, 3000);
        }
        function editMessage(id, text) {
            document.getElementById("message" + id).innerHTML = text;
        }
    </script>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th style="text-align:center;"><?php echo __('Type');?></th>
            <th style="text-align:center;"><?php echo __('Last Update');?></th>
            <th style="text-align:center;"><?php echo __('Description');?></th>
            <th style="text-align:center;"><?php echo __('Outdated');?></th>
            <th style="text-align:center;"><?php echo __('Filesize');?></th>
            <th style="text-align:center;"><?php echo __('Progress');?></th>
            <th style="text-align:center;"><?php echo __('Actions');?></th>
        </tr>
        <?php foreach ($export_types as $k => $type): ?>
            <tr>
                <td class="short"><?php echo $type['type']; ?></td>
                <td id="update<?php echo $i; ?>" class="short" style="color:red;"><?php echo $type['lastModified']; ?></td>
                <td>
                    <?php
                        echo $type['description'];
                        if ($type['canHaveAttachments']):
                            if (Configure::read('MISP.cached_attachments')):
                    ?>
                        <span class="green"> (<?php echo __('Attachments are enabled on this instance');?>)</span>
                    <?php
                            else:
                    ?>
                        <span class="red"> (<?php echo __('Attachments are disabled on this instance');?>)</span>
                    <?php
                            endif;
                        endif;
                    ?>
                </td>
                <td id="outdated<?php echo $i; ?>">
                    <?php
                        if ($type['recommendation']) {
                            echo '<span style="color:red;">' . __('Yes') . '</span>';
                        } else {
                            echo __('No');
                        }
                    ?>
                </td>
                <td class="short" style="text-align:right;">
                    <?php
                        if (isset($type['filesize'])):
                            echo h($type['filesize']);
                        else:
                    ?>
                            <span class="red"><?php echo __('N/A');?></span>
                    <?php
                        endif;
                    ?>
                </td>
                <td style="width:150px;">
                    <div id="barFrame<?php echo $i; ?>" class="progress progress-striped active" style="margin-bottom: 0px;display:none;">
                      <div id="bar<?php echo $i; ?>" class="bar" style="width: <?php echo $type['progress']; ?>%;">
                        <?php
                            if ($type['progress'] > 0 && $type['progress'] < 100) echo $type['progress'] . '%';
                        ?>
                      </div>
                    </div>
                    <div id="message<?php echo $i; ?>" style="text-align:center;display:block;"><?php echo __('Loading…');?></div>
                    <?php $temp = $i . "','" . $k . "','" . $type['job_id'] . "','" .  $type['progress'] . "','" . $type['lastModified']; ?>
                    <script type="text/javascript">
                        if ("<?php echo $type['progress']; ?>"  == 0) {
                            if ("<?php echo $type['lastModified']; ?>" != "N/A") {
                                editMessage(<?php echo $i; ?>, "Queued.");
                            } else {
                                editMessage(<?php echo $i; ?>, '<span style="color:red;"><?php echo __('N/A'); ?></span>');
                            }
                        }
                        if ("<?php echo $type['progress']; ?>" == 100) editMessage(<?php echo $i; ?>, '<?php echo "Completed."; ?>');
                        queueInterval('<?php echo $temp;?>');
                    </script>
                </td>
                <td style="width:150px;">
                    <?php
                        if ($k !== 'text') {
                            echo $this->Html->link('Download', array('action' => 'downloadExport', $k), array('class' => 'btn btn-inverse toggle-left btn.active qet'));
                        ?>
                            <button class = "btn btn-inverse toggle-right btn.active qet" id=button<?php echo $i;?> onClick = "generate('<?php echo $temp; ?>')" <?php if (!$type['recommendation']) echo 'disabled';?>><?php echo __('Generate');?></button>
                        <?php
                        } else {
                        ?>
                            <button class = "btn btn-inverse btn.active qet" id=button<?php echo $i;?> onClick = "generate('<?php echo $temp; ?>')" <?php if (!$type['recommendation']) echo 'disabled';?>><?php echo __('Generate');?></button>
                        <?php
                        }
                        ?>

                </td>
            </tr>
        <?php
            $i++;
        endforeach; ?>
    </table>
    <ul class="inline">
    <?php
    foreach ($sigTypes as $sigType): ?>
        <li class="actions" style="text-align:center; width: auto; padding: 7px 2px;">
            <?php echo $this->Html->link($sigType, array('action' => 'downloadExport', $k, $sigType), array('class' => 'btn btn-inverse btn.active qet')); ?>
        </li>
    <?php endforeach; ?>
    </ul>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'export'));
?>
<script type="text/javascript">
    function generate(i, type, id, progress, modified) {
        $.ajax({
            url: "/jobs/cache/" + type,
            })
            .done(function(data) {
                jobsArray[i] = data;
                editMessage(i, "Adding...");
                queueInterval(i, type, data, 1, "Just now");
                disableButton(i);
            });
        }

    function queryTask(type, i){
        $.getJSON('/jobs/getProgress/cache_' + type, function(data) {
            var x = document.getElementById("bar" + i);
            x.style.width = data+"%";
            if (data > -1 && data < 100) {
                x.innerHTML = data + "%";
                showDiv("barFrame" + i);
                hideDiv("message" + i);
            }
            if (data == 100) {
                clearInterval(intervalArray[i]);
                hideDiv("barFrame" + i);
                showDiv("message" + i);
                updateTime(i);
                editMessage(i, "Completed.");
                updateOutdated(i);
            }
            if (data == -1) {
                alert("<?php echo __('Warning, the background worker is not responding!');?>");
            }
        });
    }

    function showDiv(id) {
        document.getElementById(id).style.display = 'block';
    }

    function hideDiv(id) {
        document.getElementById(id).style.display = 'none';
    }

    function updateTime(id) {
        document.getElementById("update" + id).innerHTML = "<?php echo __('0 seconds ago');?>";
    }

    function updateOutdated(id) {
        document.getElementById("outdated" + id).innerHTML = "<?php echo __('No');?>";
    }

    function disableButton(id) {
        $('#button' + id).prop('disabled', true);
    }
</script>
