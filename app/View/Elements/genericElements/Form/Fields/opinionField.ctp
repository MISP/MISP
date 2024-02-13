<?php
$seed = mt_rand();
$params['type'] = 'number';
$params['min'] = 0;
$params['max'] = 100;
$params['class'] .= ' opinion-' . $seed;
echo $this->Form->input($fieldData['field'], $params);

echo $this->element('genericElements/assetLoader', [
    'css' => ['analyst-data',],
]);
?>

<script>
    var opinionGradient<?= $seed ?> = '\
        <div class="opinion-gradient-container" style="width: 10rem; height: 6px; position: relative;">\
            <div class="opinion-gradient opinion-gradient-negative"></div> \
            <div class="opinion-gradient opinion-gradient-positive"></div> \
            <input type="range" min="0" max="100" value="50" step="10" class="slider" id="opinion-slider">\
        </div> \
    '
    var opinionTemplate<?= $seed ?> = '\
        <div class="main-container" style="margin: 0.75rem 0 0.25rem 0; display: flex; flex-direction: row;" title="<?= __('Opinion:') ?> 50 /100"> \
            ' + opinionGradient<?= $seed ?> + ' \
            <span style="line-height: 1em; margin-left: 0.25rem; margin-top: -3px;"> \
                <b class="opinion-text" style="margin-left: 0.5rem; color: #333"></b> \
                <b class="opinion-value" style="margin-left: 0.25rem; color: #333"></b> \
                <span style="font-size: 0.7em; font-weight: lighter; color: #999">/100</span> \
            </span> \
        </div> \
    '
    var opinionColorScale = ['rgb(164, 0, 0)', 'rgb(166, 15, 0)', 'rgb(169, 25, 0)', 'rgb(171, 33, 0)', 'rgb(173, 40, 0)', 'rgb(175, 46, 0)', 'rgb(177, 52, 0)', 'rgb(179, 57, 0)', 'rgb(181, 63, 0)', 'rgb(183, 68, 0)', 'rgb(186, 72, 0)', 'rgb(188, 77, 0)', 'rgb(190, 82, 0)', 'rgb(191, 86, 0)', 'rgb(193, 90, 0)', 'rgb(195, 95, 0)', 'rgb(197, 98, 0)', 'rgb(198, 102, 0)', 'rgb(200, 106, 0)', 'rgb(201, 110, 0)', 'rgb(203, 114, 0)', 'rgb(204, 118, 0)', 'rgb(206, 121, 0)', 'rgb(208, 125, 0)', 'rgb(209, 128, 0)', 'rgb(210, 132, 0)', 'rgb(212, 135, 0)', 'rgb(213, 139, 0)', 'rgb(214, 143, 0)', 'rgb(216, 146, 0)', 'rgb(217, 149, 0)', 'rgb(218, 153, 0)', 'rgb(219, 156, 0)', 'rgb(220, 160, 0)', 'rgb(222, 163, 0)', 'rgb(223, 166, 0)', 'rgb(224, 169, 0)', 'rgb(225, 173, 0)', 'rgb(226, 176, 0)', 'rgb(227, 179, 0)', 'rgb(228, 182, 0)', 'rgb(229, 186, 0)', 'rgb(230, 189, 0)', 'rgb(231, 192, 0)', 'rgb(232, 195, 0)', 'rgb(233, 198, 0)', 'rgb(234, 201, 0)', 'rgb(235, 204, 0)', 'rgb(236, 207, 0)', 'rgb(237, 210, 0)', 'rgb(237, 212, 0)', 'rgb(234, 211, 0)', 'rgb(231, 210, 0)', 'rgb(229, 209, 1)', 'rgb(226, 208, 1)', 'rgb(223, 207, 1)', 'rgb(220, 206, 1)', 'rgb(218, 204, 1)', 'rgb(215, 203, 2)', 'rgb(212, 202, 2)', 'rgb(209, 201, 2)', 'rgb(206, 200, 2)', 'rgb(204, 199, 2)', 'rgb(201, 198, 3)', 'rgb(198, 197, 3)', 'rgb(195, 196, 3)', 'rgb(192, 195, 3)', 'rgb(189, 194, 3)', 'rgb(186, 193, 3)', 'rgb(183, 192, 4)', 'rgb(180, 190, 4)', 'rgb(177, 189, 4)', 'rgb(174, 188, 4)', 'rgb(171, 187, 4)', 'rgb(168, 186, 4)', 'rgb(165, 185, 4)', 'rgb(162, 183, 4)', 'rgb(159, 182, 4)', 'rgb(156, 181, 4)', 'rgb(153, 180, 4)', 'rgb(149, 179, 5)', 'rgb(146, 178, 5)', 'rgb(143, 177, 5)', 'rgb(139, 175, 5)', 'rgb(136, 174, 5)', 'rgb(133, 173, 5)', 'rgb(130, 172, 5)', 'rgb(126, 170, 5)', 'rgb(123, 169, 5)', 'rgb(119, 168, 5)', 'rgb(115, 167, 5)', 'rgb(112, 165, 6)', 'rgb(108, 164, 6)', 'rgb(104, 163, 6)', 'rgb(100, 162, 6)', 'rgb(96, 160, 6)', 'rgb(92, 159, 6)', 'rgb(88, 157, 6)', 'rgb(84, 156, 6)', 'rgb(80, 155, 6)', 'rgb(78, 154, 6)'];

    $(document).ready(function() {
        initOpinionSlider()
    })

    function getOpinionColor(opinion) {
        return opinion == 50 ? '#333' : ( opinion > 50 ? '#468847' : '#b94a48');
    }
    function getOpinionText(opinion) {
        return (opinion  >= 81) ? '<?= __("Strongly Agree") ?>' : ((opinion  >= 61) ? '<?= __("Agree") ?>' : ((opinion  >= 41) ? '<?= __("Neutral") ?>' : ((opinion  >= 21) ? '<?= __("Disagree") ?>' : '<?= __("Strongly Disagree") ?>')))
    }

    function setOpinionLevel(opinion) {
        opinion = Number.parseInt(opinion)
        var $formContainer = $('.opinion-<?= $seed ?>').parent()
        var $mainContainer = $formContainer.find('.main-container')
        var $gradientContainer = $formContainer.find('.opinion-gradient-container')
        var $opinionSlider = $gradientContainer.find('#opinion-slider')
        var backgroundColor = getOpinionColor(opinion)
        var backgroundColorDot = opinion == 50 ? '#555' : opinionColorScale[opinion]

        $mainContainer.attr('title', '<?= __('Opinion:') ?> ' + opinion + ' /100')
        $mainContainer.find('.opinion-text')
            .css('color', backgroundColor)
            .text(getOpinionText(opinion))
        $mainContainer.find('.opinion-value')
            .css('color', backgroundColor)
            .text(opinion)

        if (opinion >= 50) {
            var opinionMask = Math.abs(-50 + opinion)*2
            $gradientContainer.find('.opinion-gradient-negative').css({
                'opacity': 0,
                '-webkit-mask-image': 'unset',
                'mask-image': 'unset',
            })
            $gradientContainer.find('.opinion-gradient-positive').css({
                'opacity': 1,
                '-webkit-mask-image': 'linear-gradient(90deg, black 0 ' + opinionMask + '%, transparent ' + opinionMask + '% 100%)',
                'mask-image': 'linear-gradient(90deg, black 0 ' + opinionMask + '%, transparent ' + opinionMask + '% 100%)',
            })
        } else {
            var opinionMask = 100-(Math.abs(-50 + opinion)*2)
            $gradientContainer.find('.opinion-gradient-negative').css({
                'opacity': 1,
                '-webkit-mask-image': 'linear-gradient(90deg, transparent 0 ' + opinionMask + '%, black ' + opinionMask + '% 100%)',
                'mask-image': 'linear-gradient(90deg, transparent 0 ' + opinionMask + '%, black ' + opinionMask + '% 100%)',
            })
            $gradientContainer.find('.opinion-gradient-positive').css({
                'opacity': 0,
                '-webkit-mask-image': 'unset',
                'mask-image': 'unset'
            })
        }
        $opinionSlider.val(opinion)
        $opinionSlider[0].style.setProperty('--color', backgroundColorDot);
        $('input#OpinionOpinion').val(opinion)
    }

    function genSlider() {
        var $div = $('<div style="display: inline-block;"></div>')
        var $opinionTemplate = $(opinionTemplate<?= $seed ?>)
        var $div = $div.append($opinionTemplate)
        return $div
    }

    function initOpinionSlider() {
        var $input = $('.opinion-<?= $seed ?>')
        $input.css({
            'width': '2.5rem',
            'margin': '0 0.5rem 0 0',
        })
        $input.parent().append(genSlider())
        var currentOpinionValue = !Number.isNaN(Number.parseInt($input.val())) ? Number.parseInt($input.val()) : 50
        setOpinionLevel(currentOpinionValue)
        
        $('.opinion-<?= $seed ?>').parent().find('#opinion-slider')
            .on('input', function(e) {
                setOpinionLevel(this.value)
            })
        $input.on('input', function(e) {
            setOpinionLevel(this.value)
        })
    }
</script>

<style>
    input#opinion-slider {
        position: absolute;
        width: 160px;

        -webkit-appearance: none;
        appearance: none;
        height: 6px;
        background: #ffffff00;
        outline: none;
        opacity: 0.8;
        -webkit-transition: .2s;
        transition: opacity .2s;
    }

    #opinion-slider:hover {
       opacity: 1;
    }


    /* The slider handle (use -webkit- (Chrome, Opera, Safari, Edge) and -moz- (Firefox) to override default look) */
    #opinion-slider::-webkit-slider-thumb {
        border-radius: 50%;
        -webkit-appearance: none;
        appearance: none;
        width: 12px;
        height: 12px;
        box-shadow: 0 0 2px 0px #00000066;
        background-color: var(--color, white);
        cursor: pointer;
    }

    #opinion-slider::-moz-range-thumb {
        border-radius: 50%;
        width: 12px;
        height: 12px;
        box-shadow: 0 0 2px 0px #00000066;
        background-color: var(--color, white);
        cursor: pointer;
    }
</style>