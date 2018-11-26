<?php
if (!$isSiteAdmin) exit();
if ($updateProgress['update_prog_tot'] !== 0 ) {
    $percentageFail = floor(count($updateProgress['update_prog_failed_num']) / $updateProgress['update_prog_tot']*100);
    $percentage = floor($updateProgress['update_prog_cur'] / $updateProgress['update_prog_tot']*100);
    //$percentage -= $percentageFail; // substract failed updates
} else {
    $percentage = 100;
    $percentageFail = 0;
}
?>
<div style="width: 50%;margin: 0 auto;">
    <?php if (!is_null($updateProgress['update_prog_msg'])): ?>
        <h2><?php echo(__('Update progress'));?></h2>
        <div class="" style="max-width: 1000px;">
            
            <div class="progress progress-striped" style="max-width: 1000px;">
                <div id="pb-progress" class="bar" style="font-weight: bold; width: <?php echo h($percentage);?>%;"><?php echo h($percentage);?>%</div>
                <div id="pb-fail" class="bar" style="width: <?php echo h($percentageFail);?>%; background-color: #ee5f5b;"></div>
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
                        $rowFail = in_array($i, $updateProgress['update_prog_failed_num']);
                        $rowClass = '';
                        $rowIcon =  '<i id="icon-' . $i . '" class="fa"></i>';
                        if ($rowDone) {
                            $rowClass =  'class="alert alert-success"';
                            $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-check-circle-o"></i>';
                        }
                        if ($rowCurrent && !$rowFail) {
                            $rowClass =  'class="alert alert-info"';
                            $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-cogs"></i>';
                        } else if ($rowFail) {
                            $rowClass =  'class="alert alert-danger"';
                            $rowIcon =  '<i id="icon-' . $i . '" class="fa fa-times-circle-o"></i>';
                        }

                        if (isset($updateProgress['update_prog_msg']['time']['started'][$i])) {
                            $datetimeStart = $updateProgress['update_prog_msg']['time']['started'][$i];
                            if (isset($updateProgress['update_prog_msg']['time']['elapsed'][$i])) {
                                $updateDuration = $updateProgress['update_prog_msg']['time']['elapsed'][$i];
                            } else { // compute elapsed based on started
                                $temp = new DateTime();
                                $temp->sub(new DateTime($datetimeStart));
                                $diff = $temp->diff(new DateTime($messages['time']['started'][$index]));
                                $updateDuration = $diff->format('%H:%I:%S');
                            }
                        } else {
                            $datetimeStart = '';
                            $updateDuration = '';
                        }
                    ?>
                        <tr id="row-<?php echo $i; ?>" <?php echo $rowClass; ?> >
                            <td><?php echo $rowIcon; ?></td>
                            <td>
                                <div>
                                    <a style="cursor: pointer; maring-bottom: 2px;" onclick="toggleVisiblity(<?php echo $i;?>)">
                                        <span class="foldable fa fa-terminal"></span>
                                        <?php echo __('Update ') . ($i+1); ?>
                                        <span class="inline-term"><?php echo h(substr($cmd, 0, 60)) . (strlen($cmd) > 60 ? '[...]' : '' );?></span>
                                        <span class="label">
                                            <?php echo __('Started @ '); ?>
                                            <span id="startedTime-<?php echo $i; ?>"><?php echo h($datetimeStart); ?></span>
                                        </span>
                                        <span class="label">
                                            <?php echo __('Elapsed Time @ '); ?>
                                            <span id="elapsedTime-<?php echo $i; ?>"><?php echo h($updateDuration); ?></span>
                                        </span>

                                    </a>
                                    <div data-terminalid="<?php echo $i;?>" style="display: none; margin-top: 5px;">
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
    function toggleVisiblity(termId, auto, show) {
        var term = $('div[data-terminalid='+termId+']')
        if (auto === true) {
            if (term.data('manual') !== true) { //  show if manual is not set
                if (show === true) {
                    term.show();
                } else if (show === false) {
                    term.hide();
                } else {
                    term.toggle();
                }
            }
        } else {
            term.data('manual', true);
            if (show === true) {
                term.show();
            } else if (show === false) {
                term.hide();
            } else {
                term.toggle();
            }
        }
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
            var failArray = data['update_prog_failed_num'];
            for (var i=0; i<tot; i++) {
                var term = $('div[data-terminalid='+i+']')
                toggleVisiblity(i, true, false);   
                if (i < cur) {
                    if (failArray.indexOf(String(i)) != -1) {
                        update_row_state(i, 2);
                    } else {
                        update_row_state(i, 0);
                    }
                } else if (i == cur) {
                    if (failArray.indexOf(String(i)) != -1) {
                        update_row_state(i, 2);
                        toggleVisiblity(i, true, true);   
                    } else {
                        update_row_state(i, 1);
                        toggleVisiblity(i-1, true, true);   
                    }
                } else {
                    update_row_state(i, 3);
                }
            }
            update_messages(data['update_prog_msg']);
            if (tot > 0) {
                var percFail = Math.round(failArray.length/tot*100);
                //var perc = Math.round(cur/tot*100) - percFail;
                var perc = Math.round(cur/tot*100);
                update_pb(perc, percFail);
            }

            if (cur >= tot || failArray.indexOf(cur) != -1) {
                //clearInterval(pooler);
            }
        });
    }


    function update_messages(messages) {
        if (messages.cmd === undefined) {
            return;
        }
        messages.cmd.forEach(function(msg, i) {
            var div = $('#termcmd-'+i);
            create_spans_from_message(div, msg);
        });
        messages.res.forEach(function(msg, i) {
            var div = $('#termres-'+i);
            div.css('display', '');
            create_spans_from_message(div, msg);
        });
        messages.time.started.forEach(function(startedText, i) {
            var elapsedText = messages.time.elapsed[i];
            if (elapsedText === undefined) {
                var diff = new Date((new Date()).getTime() - (new Date(startedText)).getTime());
                elapsedText = pad(diff.getUTCHours(), 2)
                    + ':' + pad(diff.getUTCMinutes(), 2)
                    + ':' + pad(diff.getUTCSeconds(), 2);
            }
            update_times(i, startedText, elapsedText)
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

    function update_pb(perc, percFail) {
        var pb = $('#pb-progress');
        pb.css('width', perc+'%');
        pb.text(perc+'%');
        var pbF = $('#pb-fail');
        pbF.css('width', percFail+'%');
    }

    function update_times(i, startedText, elapsedText) {
        var started = $('#startedTime-'+i);
        var elapsed = $('#elapsedTime-'+i);
        started.text(startedText);
        elapsed.text(elapsedText);
    }

    function pad(num, size){ return ('000000000' + num).substr(-size); }
</script>
