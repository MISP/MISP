<?php
if (!$isSiteAdmin) exit();
if ($updateProgress['update_prog_tot'] !== 0 ) {
    $percentage = floor($updateProgress['update_prog_cur'] / $updateProgress['update_prog_tot']*100);
} else {
    $percentage = 100;
}
?>
<div style="width: 50%;margin: 0 auto;">
    <?php if (!is_null($updateProgress['update_prog_msg'])): ?>
        <h2><?php echo(__('Update progress'));?></h2>
        <div class="" style="max-width: 1000px;">
            
            <div class="progress progress-striped" style="max-width: 1000px;">
                <div class="bar" style="width: <?php echo h($percentage);?>%;"><?php echo h($percentage);?>%</div>
            </div>

            <table class="table table-bordered table-stripped updateProgressTable">
                <thead>
                    <tr>
                        <th></th>
                        <th>Update command</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($updateProgress['update_prog_msg']['cmd'] as $i => $cmd):
                        if (isset($updateProgress['update_prog_msg']['res'][$i])) {
                            $res = $updateProgress['update_prog_msg']['res'][$i];
                        } else {
                            $res = false;
                        }
                        $rowDone = $i < $updateProgress['update_prog_cur'];
                        $rowCurrent = $i === $updateProgress['update_prog_cur'];
                        $rowFail = $i === $updateProgress['update_prog_failed_num'];
                        $rowClass = '';
                        $rowIcon =  '<i id="icon-' . $i . '" class="fa"></i>';
                        if ($rowDone) {
                            $rowClass =  'class="alert alert-success"';
                            $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-check-circle-o"></i>';
                        } else if ($rowCurrent && !$rowFail) {
                            $rowClass =  'class="alert alert-info"';
                            $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-cogs"></i>';
                        } else if ($rowFail) {
                            $rowClass =  'class="alert alert-danger"';
                            $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-times-circle-o"></i>';
                        }
                    ?>
                        <tr id="row-<?php echo $i; ?>" <?php echo $rowClass; ?> >
                            <td><?php echo $rowIcon; ?></td>
                            <td>
                                <div>
                                    <a style="cursor: pointer;" onclick="toggleVisiblity(this, <?php echo $i;?>)">
                                        <span class="foldable fa fa-terminal"></span>
                                            <?php echo __('Update ') . ($i+1); ?>
                                    </a>
                                    <div data-terminalid="<?php echo $i;?>" style="<?php echo !$rowFail ? 'display: none;' : ''; ?>">
                                        <div id="termcmd-<?php echo $i;?>" class="div-terminal">
                                            <?php
                                                $temp = preg_replace('/^\n*\s+/', '', $cmd);
                                                $temp = preg_split('/\s{4,}/m', $temp);
                                                foreach ($temp as $j => $line) {
                                                    $pad = $j > 0 ? '30' : '0';
                                                    if ($line !== '') {
                                                        echo '<span style="margin-left: ' . $pad . 'px;">' . h($line) . '</span>';
                                                    }
                                                }
                                            ?>
                                        </div>
                                        <div>
                                            <span class="fa fa-level-up terminal-res-icon"></span>
                                            <div id="termres-<?php echo $i;?>" class="div-terminal terminal-res">
                                                <?php
                                                    if ($res !== false) {
                                                        $temp = preg_replace('/^\n*\s+/', '', $res);
                                                        $temp = preg_split('/\s{2,}/m', $temp);
                                                        foreach ($temp as $j => $line) {
                                                            $pad = $j > 0 ? '30' : '0';
                                                            if ($line !== '') {
                                                                echo '<span style="margin-left: ' . $pad . 'px;">' . h($line) . '</span>';
                                                            }
                                                        }
                                                    }
                                                ?>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
    </div>
    <?php else: ?>
        <h2><?php echo __('No update in progress'); ?></h2>
    <?php endif; ?>

</div>

<script>
    function toggleVisiblity(clicked, termId) {
        $('div[data-terminalid='+termId+']').toggle();
    }

    var updateProgress = <?php echo json_encode($updateProgress); ?>;;
    var pooler;
    var poolerInterval = 3000;
    $(document).ready(function() {
        pooler = setInterval(function() { update_state(); }, poolerInterval);
    });


    function update_state() {
        var url = "<?php echo $baseurl; ?>/servers/quickUpdateProgress";
        $.getJSON(url, function(data) {
            var tot = parseInt(data['update_prog_tot']);
            var cur = parseInt(data['update_prog_cur']);
            var fail = parseInt(data['update_prog_failed_num']);
            for (var i=0; i<tot; i++) {
                $('div[data-terminalid='+i+']').hide();
                if (i < cur) {
                    update_row_state(i, 0);
                } else if (i == cur) {
                    if (i == fail) {
                        update_row_state(i, 2);
                        $('div[data-terminalid='+i+']').show();
                    } else {
                        update_row_state(i, 1);
                        $('div[data-terminalid='+(i-1)+']').show();
                    }
                } else {
                    update_row_state(i, 3);
                }
            }
            update_messages(data['update_prog_msg']);
            if (tot > 0) {
                var perc = Math.round(cur/tot*100);
                update_pb(perc);
            }

            if (cur >= tot || cur === fail) {
                clearInterval(pooler);
            }
        });
    }


    function update_messages(messages) {
        messages.cmd.forEach(function(msg, i) {
            var div = $('#termcmd-'+i);
            create_spans_from_message(div, msg);
        });
        messages.res.forEach(function(msg, i) {
            var div = $('#termres-'+i);
            div.css('display', '');
            create_spans_from_message(div, msg);
        });
    }

    function create_spans_from_message(toAppendto, msg) {
        toAppendto.empty();
        // create span for each line of text
        msg = msg.replace(/^\n*\s+/, '');
        var lines = msg.split(/\s{2,}/m)
        lines.forEach(function(line, j) {
            var pad = j > 0 ? '30' : '0';
            if (line !== '') {
                var span = $('<span style="margin-left: ' + pad + 'px;">' + line + '</span>');
                toAppendto.append(span);
            }
        });
    }

    function update_row_state(i, state) {
        var icon = $('#icon-'+i);
        var row = $('#row-'+i);
        switch(state) {
            case 0: // success
                row.removeClass('alert-danger alert-info');
                row.addClass('alert-success');
                icon.removeClass('fa-times-circle-o fa-cogs');
                icon.addClass('fa-check-circle-o');
                break;
            case 1: // current
                row.removeClass('alert-success alert-danger');
                row.addClass('alert-info');
                icon.removeClass('fa-check-circle-o', 'fa-times-circle-o');
                icon.addClass('fa-cogs');
                break;
            case 2: //fail
                row.removeClass('alert-success alert-info');
                row.addClass('alert-danger');
                icon.removeClass('fa-check-circle-o fa-cogs');
                icon.addClass('fa-times-circle-o');
                break;
            case 3: //no state
            default:
                row.removeClass('alert-success alert-info alert-danger');
                icon.removeClass('fa-check-circle-o fa-times-circle-o fa-cogs');
                break;
        }
    }

    function update_pb(perc) {
        var pb = $('div.bar');
        pb.css('width', perc+'%');
        pb.text(perc+'%');
    }
</script>
