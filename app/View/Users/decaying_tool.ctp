<div class="view">

<h2>Decaying Of Indicator Fine Tuning Tool</h2>

<div class="row">
    <div class="span5">
        <div style="height: calc(100vh - 180px); overflow-y: scroll;">
            <table class="table table-striped table-bordered">
                <thead>
                    <tr>
                        <th></th>
                        <th>Attribute Type</th>
                        <th>Model Name</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($types as $type => $value): ?>
                        <tr>
                            <td><input type="checkbox"></input></td>
                            <td class="useCursorPointer" onclick="toggleCB(this);"><?php echo h($type); ?></td>
                            <td></td>
                            <td>
                                <span class="fa fa-check-circle"></span>
                                <button class="btn btn-primary btn-mini"><span class="fa fa-arrow-up"></span></button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <div class="span12">
        <div style="border: 1px solid #ddd; border-radius: 4px; margin-bottom: 20px;">
            <canvas id="decayGraph" style="width: 100%;"></canvas>
        </div>
        <div>
            <div class="span6" style="margin-bottom: 20px;">
                <?php foreach ($parameters as $param => $config): ?>
                    <div class="input-prepend input-append">
                        <span class="add-on" style="min-width: 70px;"><?php echo h($param) . (isset($config['greek']) ? ' <strong>'.h($config['greek']).'</strong>' : ''); ?></span>
                        <input id="input_<?php echo h($param); ?>" class="input-mini" type="number" min=0 step=<?php echo h($config['step']); ?> value=<?php echo h($config['value']); ?> oninput="refreshGraph(this);" ></input>
                        <span class="add-on"><input id="input_<?php echo h($param); ?>_range" type="range" min=0 <?php echo isset($config['max']) ? 'max=' . $config['max'] : '' ?> step=<?php echo h($config['step']); ?> value=<?php echo h($config['value']); ?> oninput="$('#input_<?php echo h($param); ?>').val(this.value).trigger('input');"></input></span>
                        <?php if (isset($config['unit'])): ?>
                            <span class="add-on"><?php echo h($config['unit']); ?></span>
                        <?php endif; ?>

                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="row">
            <div class="span12">
                <table class="table table-striped table-bordered">
                    <thead>
                        <tr>
                            <th>Model Name</th>
                            <th>Parameters</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($savedModels as $model => $values): ?>
                            <tr>
                                <td></td>
                                <td></td>
                                <td></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</div>

</div>

<?php echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view')); ?>
<?php echo $this->Html->script('Chart.min'); ?>

<script>
function toggleCB(clicked) {
    $clicked = $(clicked);
    var cb = $clicked.parent().first().find('input');
    cb.prop('checked', !cb.is(':checked'));
}

function getScore(x, base_score) {
    if (base_score === undefined) {
        base_score = 100;
    }
    var delta = parseFloat($('#input_Delta').val());
    var tau = parseInt($('#input_Tau').val() * 24);
    return (base_score * (1 - Math.pow(x / tau, 1/delta))).toFixed(2);
}

function getReverseScore(y, base_score) {
    if (base_score === undefined) {
        base_score = 100;
    }
    var delta = parseFloat($('#input_Delta').val());
    var tau = parseInt($('#input_Tau').val() * 24);
    return (tau * Math.pow(1 - (y / base_score), delta)).toFixed(2);
}

function genDecay() {
    var threshold = parseInt($('#input_Threshold').val());
    return genAxis().map(function(e, x) {
        var y = getScore(x);
        return y >= threshold ? y : NaN;
    });
}

function genLine() {
    return genAxis().map(function(e) {
        return $('#input_Threshold').val();
    });
}

function genAxis(textLabel) {
    var tau = parseInt($('#input_Tau').val() * 24);

    var data = [];
    for (var i=0; i<(tau+1); i++) {
        data.push(i);
    }

    return data;
}

function refreshGraph(updated) {
    var $this = $(updated);
    var id = $this.attr('id');
    var val = parseInt($this.val());
    var datasetDecay = chart.data.datasets[0];
    var updateOption = {};
    switch(id) {
        case 'input_Threshold':
            var val = parseInt($('#input_Threshold').val());
            for(var i=0; i<chart.data.datasets[1].data.length; i++) {
                chart.data.datasets[1].data[i] = val;
            }
            chart.data.datasets[0].data = genDecay();
            break;
        case 'input_Tau':
            chart.data.labels = genAxis();
            chart.data.datasets[0].data = genDecay();
            chart.data.datasets[1].data = genLine();
            updateOption['duration'] = 0;
            break;
        case 'input_Delta':
            // chart.data.labels.forEach(function (x, i) {
            //     chart.data.datasets[0].data[i] = getScore(x);
            // });
            chart.data.datasets[0].data = genDecay();
            break;
        default:
            break;
    }
    $('#'+id+'_range').val($this.val());
    chart.update(updateOption);
}

var chart;
$(document).ready(function() {
    var ctx = $('#decayGraph');
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: genAxis(),
            datasets: [
                {
                    label: 'Decay over time',
                    data: genDecay(),
                    borderColor: 'rgba(91, 183, 91, 0.7)',
                    backgroundColor: 'rgba(91, 183, 91, 0.3)',
                    cubicInterpolationMode: 'monotone',
                    fill: 1,
                    pointRadius: 0
                },
                {
                    label: 'Threshold',
                    data: genLine(),
                    borderColor: 'rgba(255, 99, 132, 0.7)',
                    backgroundColor: 'rgba(255, 99, 132, 0.3)',
                    pointRadius: 0
                },
            ]
        },
        options: {
            responsive: true,
            title: {
                display: false
            },
            scales: {
                xAxes: [{
                    scaleLabel: {
                        display: true,
                        labelString: 'Days',
                    },
                    ticks: {
                        callback: function(hour, index, values) {
                            var d = parseInt(hour / 24);
                            return hour % 24 == 0 ? d : null;
                        }
                    }
                }],
                yAxes: [{
                    scaleLabel: {
                        display: true,
                        labelString: 'Decay Score',
                    },
                    ticks: {
                        suggestedMin: 0,
                        suggestedMax: 100
                    }
                }]
            },
            tooltips: {
                position: 'nearest',
                mode: 'index',
                intersect: false,
                callbacks: {
                    title: function(tooltipItem, data)  {
                        var days = parseInt(tooltipItem[0].index / 24);
                        var hours = parseInt(tooltipItem[0].index % 24);
                        var text = "After "
                            + days
                            + (days>1 ? " days" : " day");
                        if (hours > 0) {
                            text += " and " + hours + (hours>1 ? " hours" : " hour");
                        }
                        return text;
                    },
                    label: function(tooltipItem, data)  {
                        var label = data.datasets[tooltipItem.datasetIndex].label;
                        if (label != 'Threshold') {
                            label = "Score";
                        }
                        label += ": " + data.datasets[tooltipItem.datasetIndex].data[tooltipItem.index];
                        return label;
                    }
                }
            },
        }
    });
});
</script>
