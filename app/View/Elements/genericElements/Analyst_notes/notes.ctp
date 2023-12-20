<?php if (empty($notes)) {
    return;
}
$seed = mt_rand();
?>

<i class="<?= $this->FontAwesome->getClass('sticky-note') ?> useCursorPointer" onclick="openNotes(this)" title="<?= __('Notes and opinions for this UUID') ?>"></i>

<script>
    var notes = <?= json_encode($notes) ?>;
    var shortDist = <?= json_encode($shortDist) ?>;
    var renderedNotes = null

    var nodeContainerTemplate = doT.template('\
        <div style="display: flex; flex-direction: column; gap: 0.5rem;">{{=it.content}}</div> \
    ')
    var baseNoteTemplate = doT.template('\
        <div id="note-{{=it.id}}" \
            style="display: flex; flex-direction: row; align-items: center; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 1px 5px -2px rgb(0 0 0 / 0.5); border-radius: 0.25rem; padding: 0.25rem; margin-bottom: 0.0rem; background-color: #fff" \
        > \
            <div style="flex-grow: 1;"> \
                <div style="display: flex; flex-direction: column;"> \
                    <div style="display: flex; min-width: 250px; gap: 0.5rem;"> \
                        <img src="<?= $baseurl ?>/img/orgs/{{=it.Organisation.id}}.png" width="20" height="20" class="orgImg" onerror="this.remove()" alt="Organisation logo"></object> \
                        <span style="margin-left: 0rem; margin-right: 0.5rem;"> \
                            <span>{{=it.Organisation.name}}</span> \
                            <i class="<?= $this->FontAwesome->getClass('angle-right') ?>" style="color: #999; margin: 0 0.25rem;"></i> \
                            <b>{{=it.authors}}</b> \
                        </span> \
                        <span style="display: inline-block; font-weight: lighter; color: #999">{{=it.modified_relative}} • {{=it.modified}}</span> \
                        </i><span style="margin-left: 0.5rem; flex-grow: 1; text-align: right; color: {{=it.distribution_color}}">{{=it.distribution_text}}</span> \
                        <i style="color: #777; margin: 0 0.5rem;">•</i> \
                        <span style="margin-left: auto; display: flex;"> \
                            <span role="button"><i title="<?= __('Add an opinion to this note') ?>" class="<?= $this->FontAwesome->getClass('gavel') ?> useCursorPointer"></i></button> \
                            <span role="button"><i title="<?= __('Add a note to this note') ?>" class="<?= $this->FontAwesome->getClass('comment-alt') ?> useCursorPointer"></i></button> \
                            <span role="button"><i title="<?= __('Edit this note') ?>" class="<?= $this->FontAwesome->getClass('edit') ?> useCursorPointer"></i></button> \
                            <span role="button"><i title="<?= __('Delete this note') ?>" class="<?= $this->FontAwesome->getClass('trash') ?> useCursorPointer"></i></button> \
                        </span> \
                    </div> \
                    <div style="">{{=it.content}}</div> \
                </div> \
            </div> \
        </div> \
    ')
    var analystTemplate = doT.template('\
        {{=it.analyst_note}} \
    ')
    var opinionStars = '\
        <div style="display: flex; width: fit-content;" class="star-opinion-container-<?= $seed ?>"> \
            <i class="<?= $this->FontAwesome->getClass('star') ?> star-opinion"></i> \
            <i class="<?= $this->FontAwesome->getClass('star') ?> star-opinion"></i> \
            <i class="<?= $this->FontAwesome->getClass('star') ?> star-opinion"></i> \
            <i class="<?= $this->FontAwesome->getClass('star') ?> star-opinion"></i> \
            <i class="<?= $this->FontAwesome->getClass('star') ?> star-opinion"></i> \
        </div> \
    '
    var opinionGradient = '\
        <div class="opinion-gradient-container" style="width: 10rem; height: 6px;">\
            <span class="opinion-gradient-dot"></span> \
            <div class="opinion-gradient opinion-gradient-negative"></div> \
            <div class="opinion-gradient opinion-gradient-positive"></div> \
        </div> \
    '
    var opinionTemplate = doT.template('\
        <div style="margin: 0.75rem 0 0.25rem 0; display: flex; flex-direction: row;" title="<?= __('Opinion:') ?> {{=it.opinion}} /100"> \
            ' + opinionGradient + ' \
            <span style="line-height: 1em; margin-left: 0.25rem; margin-top: -3px;"> \
                <b style="margin-left: 0.5rem; color: {{=it.opinion_color}}">{{=it.opinion_text}}</b> \
                <b style="margin-left: 0.25rem; color: {{=it.opinion_color}}">{{=it.opinion}}</b> \
                <span style="font-size: 0.7em; font-weight: lighter; color: #999">/100</span> \
            </span> \
        </div> \
        <div style="max-width: 40vw;">{{=it.comment}}</div> \
    ')
    var replyNoteTemplate = doT.template('\
        <div style="display: flex; flex-direction: column; gap: 0.5rem; margin-left: 3px; border-left: 4px solid #ccccccaa; background: #0035dc10; padding: 0.5rem; border-radius: 5px; border-top-left-radius: 0;"> \
            {{=it.notes_html}} \
        </div> \
    ')
    var addNoteButton = '<button class="btn btn-small btn-block btn-primary" type="button"> \
        <i class="<?= $this->FontAwesome->getClass('plus') ?>"></i> <?= 'Add a note' ?> \
    </button>'

    function toggleNotes(clicked) {
        var $container = $('.note-container-<?= $seed ?>')
        $container.toggle()
    }

    function openNotes(clicked) {
        openPopover(clicked, renderedNotes, undefined, undefined, function() {
            $('.popover').css('top', '150px')
        })
    }

    function renderNotes(notes) {
        var renderedNotesArray = []
        notes.forEach(function(note) {
            var noteHtml = renderNote(note)

            if (note.notes) { // The notes has more notes attached
                noteHtml += replyNoteTemplate({notes_html: renderNotes(note.notes)})
            }

            renderedNotesArray.push(noteHtml)
        });
        return renderedNotesArray.join('')
    }

    function renderNote(note) {
        note.modified_relative = note.modified.date ? moment(note.modified.date).fromNow() : note.modified
        note.created_relative = note.created.date ? moment(note.created.date).fromNow() : note.created
        note.modified = note.modified.date ? (new Date(note.modified.date)).toLocaleString() : note.modified
        note.created = note.created.date ? (new Date(note.created.date)).toLocaleString() : note.created
        note.distribution_text = note.distribution != 4 ? shortDist[note.distribution] : note.SharingGroup.name
        note.distribution_color = note.distribution == 0 ? '#ff0000' : (note.distribution == 4 ? '#0000ff' : '#000')
        note.authors = Array.isArray(note.authors) ? note.authors.join(', ') : note.authors;
        if (note.note_type == 0) { // analyst note
            note.content = analystTemplate(note)
        } else if (note.note_type == 1) { // opinion
            note.opinion_color = note.opinion > 50 ? '#468847' : '#b94a48';
            note.opinion_text = (note.opinion  >= 81) ? '<?= __("Strongly Agree") ?>' : ((note.opinion  >= 61) ? '<?= __("Agree") ?>' : ((note.opinion  >= 41) ? '<?= __("Neutral") ?>' : ((note.opinion  >= 21) ? '<?= __("Disagree") ?>' : '<?= __("Strongly Disagree") ?>')))
            note.content = opinionTemplate(note)
        } else {
            note.content = 'INVALID NOTE TYPE'
        }
        var noteHtml = baseNoteTemplate(note)
        return noteHtml
    }

    function renderAllNotesWithForm() {
        renderedNotes = nodeContainerTemplate({content: renderNotes(notes) + addNoteButton})
    }

    $(document).ready(function() {
        renderAllNotesWithForm()
    })
</script>

<style>
    .opinion-gradient-container {
        display: flex;
        position: relative;
        background: #ccc;
        border-radius: 3px;
    }
    .opinion-gradient {
        display: inline-block;
        position: relative;
        height: 100%;
        width: 50%;
    }
    .opinion-gradient-positive {
        border-radius: 0 3px 3px 0;
        background-image: linear-gradient(90deg, rgb(237, 212, 0), rgb(236, 211, 0), rgb(234, 211, 0), rgb(233, 210, 0), rgb(231, 210, 0), rgb(230, 209, 1), rgb(229, 209, 1), rgb(227, 208, 1), rgb(226, 208, 1), rgb(224, 207, 1), rgb(223, 207, 1), rgb(222, 206, 1), rgb(220, 206, 1), rgb(219, 205, 1), rgb(218, 204, 1), rgb(216, 204, 2), rgb(215, 203, 2), rgb(213, 203, 2), rgb(212, 202, 2), rgb(211, 202, 2), rgb(209, 201, 2), rgb(208, 201, 2), rgb(206, 200, 2), rgb(205, 200, 2), rgb(204, 199, 2), rgb(202, 199, 2), rgb(201, 198, 3), rgb(199, 197, 3), rgb(198, 197, 3), rgb(197, 196, 3), rgb(195, 196, 3), rgb(194, 195, 3), rgb(192, 195, 3), rgb(191, 194, 3), rgb(189, 194, 3), rgb(188, 193, 3), rgb(186, 193, 3), rgb(185, 192, 4), rgb(183, 192, 4), rgb(182, 191, 4), rgb(180, 190, 4), rgb(179, 190, 4), rgb(177, 189, 4), rgb(175, 189, 4), rgb(174, 188, 4), rgb(173, 188, 4), rgb(171, 187, 4), rgb(170, 186, 4), rgb(168, 186, 4), rgb(167, 185, 4), rgb(165, 185, 4), rgb(164, 184, 4), rgb(162, 183, 4), rgb(161, 183, 4), rgb(159, 182, 4), rgb(158, 182, 4), rgb(156, 181, 4), rgb(154, 180, 4), rgb(153, 180, 4), rgb(151, 179, 4), rgb(149, 179, 5), rgb(148, 178, 5), rgb(146, 178, 5), rgb(144, 177, 5), rgb(143, 177, 5), rgb(141, 176, 5), rgb(139, 175, 5), rgb(138, 175, 5), rgb(136, 174, 5), rgb(134, 173, 5), rgb(133, 173, 5), rgb(131, 172, 5), rgb(130, 172, 5), rgb(128, 171, 5), rgb(126, 170, 5), rgb(125, 170, 5), rgb(123, 169, 5), rgb(121, 168, 5), rgb(119, 168, 5), rgb(117, 167, 5), rgb(115, 167, 5), rgb(113, 166, 6), rgb(112, 165, 6), rgb(110, 165, 6), rgb(108, 164, 6), rgb(106, 163, 6), rgb(104, 163, 6), rgb(102, 162, 6), rgb(100, 162, 6), rgb(98, 161, 6), rgb(96, 160, 6), rgb(94, 159, 6), rgb(92, 159, 6), rgb(90, 158, 6), rgb(88, 157, 6), rgb(86, 157, 6), rgb(84, 156, 6), rgb(82, 155, 6), rgb(80, 155, 6),rgb(78, 154, 6))
    }
    .opinion-gradient-negative {
        border-radius: 3px 0 0 3px;
        background-image: linear-gradient(90deg, rgb(164, 0, 0), rgb(165, 8, 0), rgb(166, 15, 0), rgb(167, 21, 0), rgb(169, 25, 0), rgb(170, 30, 0), rgb(171, 33, 0), rgb(172, 37, 0), rgb(173, 40, 0), rgb(174, 43, 0), rgb(175, 46, 0), rgb(176, 49, 0), rgb(177, 52, 0), rgb(178, 55, 0), rgb(179, 57, 0), rgb(180, 60, 0), rgb(181, 63, 0), rgb(182, 65, 0), rgb(183, 68, 0), rgb(184, 70, 0), rgb(186, 72, 0), rgb(187, 75, 0), rgb(188, 77, 0), rgb(189, 80, 0), rgb(190, 82, 0), rgb(190, 84, 0), rgb(191, 86, 0), rgb(192, 88, 0), rgb(193, 90, 0), rgb(194, 92, 0), rgb(195, 95, 0), rgb(196, 96, 0), rgb(197, 98, 0), rgb(197, 100, 0), rgb(198, 102, 0), rgb(199, 104, 0), rgb(200, 106, 0), rgb(201, 108, 0), rgb(201, 110, 0), rgb(202, 112, 0), rgb(203, 114, 0), rgb(204, 116, 0), rgb(204, 118, 0), rgb(205, 119, 0), rgb(206, 121, 0), rgb(207, 123, 0), rgb(208, 125, 0), rgb(208, 127, 0), rgb(209, 128, 0), rgb(210, 130, 0), rgb(210, 132, 0), rgb(211, 134, 0), rgb(212, 135, 0), rgb(212, 137, 0), rgb(213, 139, 0), rgb(214, 141, 0), rgb(214, 143, 0), rgb(215, 144, 0), rgb(216, 146, 0), rgb(216, 148, 0), rgb(217, 149, 0), rgb(217, 151, 0), rgb(218, 153, 0), rgb(219, 154, 0), rgb(219, 156, 0), rgb(220, 158, 0), rgb(220, 160, 0), rgb(221, 161, 0), rgb(222, 163, 0), rgb(222, 164, 0), rgb(223, 166, 0), rgb(223, 168, 0), rgb(224, 169, 0), rgb(225, 171, 0), rgb(225, 173, 0), rgb(226, 174, 0), rgb(226, 176, 0), rgb(227, 178, 0), rgb(227, 179, 0), rgb(227, 181, 0), rgb(228, 182, 0), rgb(228, 184, 0), rgb(229, 186, 0), rgb(229, 187, 0), rgb(230, 189, 0), rgb(230, 190, 0), rgb(231, 192, 0), rgb(231, 193, 0), rgb(232, 195, 0), rgb(232, 196, 0), rgb(233, 198, 0), rgb(233, 200, 0), rgb(234, 201, 0), rgb(234, 203, 0), rgb(235, 204, 0), rgb(235, 206, 0), rgb(236, 207, 0), rgb(236, 209, 0), rgb(237, 210, 0), rgb(237, 212, 0));
    }
    .opinion-gradient-dot {
        width: 12px;
        height: 12px;
        position: absolute;
        top: -3px;
        z-index: 10;
        box-shadow: 0 0 2px 0px #00000066;
        border-radius: 50%;
        background-color: white;
    }

    .star-opinion {
        display: inline-block;
        position: relative;
        color: #d3d3d3;
    }

<?php
if(!function_exists("genStyleForOpinionNotes")) {
    function genStyleForOpinionNotes($notes) {
        foreach ($notes as $note) {
            genStyleForOpinionNote($note);
            if (!empty($note['notes'])) {
                genStyleForOpinionNotes($note['notes']);
            }
        }
    }
}
if(!function_exists("genStyleForOpinionNote")) {
    function genStyleForOpinionNote($note) {
        if ($note['note_type'] != 1) { // opinion
            return;
        }
        $opinion_color_scale_100 = ['rgb(164, 0, 0)', 'rgb(166, 15, 0)', 'rgb(169, 25, 0)', 'rgb(171, 33, 0)', 'rgb(173, 40, 0)', 'rgb(175, 46, 0)', 'rgb(177, 52, 0)', 'rgb(179, 57, 0)', 'rgb(181, 63, 0)', 'rgb(183, 68, 0)', 'rgb(186, 72, 0)', 'rgb(188, 77, 0)', 'rgb(190, 82, 0)', 'rgb(191, 86, 0)', 'rgb(193, 90, 0)', 'rgb(195, 95, 0)', 'rgb(197, 98, 0)', 'rgb(198, 102, 0)', 'rgb(200, 106, 0)', 'rgb(201, 110, 0)', 'rgb(203, 114, 0)', 'rgb(204, 118, 0)', 'rgb(206, 121, 0)', 'rgb(208, 125, 0)', 'rgb(209, 128, 0)', 'rgb(210, 132, 0)', 'rgb(212, 135, 0)', 'rgb(213, 139, 0)', 'rgb(214, 143, 0)', 'rgb(216, 146, 0)', 'rgb(217, 149, 0)', 'rgb(218, 153, 0)', 'rgb(219, 156, 0)', 'rgb(220, 160, 0)', 'rgb(222, 163, 0)', 'rgb(223, 166, 0)', 'rgb(224, 169, 0)', 'rgb(225, 173, 0)', 'rgb(226, 176, 0)', 'rgb(227, 179, 0)', 'rgb(228, 182, 0)', 'rgb(229, 186, 0)', 'rgb(230, 189, 0)', 'rgb(231, 192, 0)', 'rgb(232, 195, 0)', 'rgb(233, 198, 0)', 'rgb(234, 201, 0)', 'rgb(235, 204, 0)', 'rgb(236, 207, 0)', 'rgb(237, 210, 0)', 'rgb(237, 212, 0)', 'rgb(234, 211, 0)', 'rgb(231, 210, 0)', 'rgb(229, 209, 1)', 'rgb(226, 208, 1)', 'rgb(223, 207, 1)', 'rgb(220, 206, 1)', 'rgb(218, 204, 1)', 'rgb(215, 203, 2)', 'rgb(212, 202, 2)', 'rgb(209, 201, 2)', 'rgb(206, 200, 2)', 'rgb(204, 199, 2)', 'rgb(201, 198, 3)', 'rgb(198, 197, 3)', 'rgb(195, 196, 3)', 'rgb(192, 195, 3)', 'rgb(189, 194, 3)', 'rgb(186, 193, 3)', 'rgb(183, 192, 4)', 'rgb(180, 190, 4)', 'rgb(177, 189, 4)', 'rgb(174, 188, 4)', 'rgb(171, 187, 4)', 'rgb(168, 186, 4)', 'rgb(165, 185, 4)', 'rgb(162, 183, 4)', 'rgb(159, 182, 4)', 'rgb(156, 181, 4)', 'rgb(153, 180, 4)', 'rgb(149, 179, 5)', 'rgb(146, 178, 5)', 'rgb(143, 177, 5)', 'rgb(139, 175, 5)', 'rgb(136, 174, 5)', 'rgb(133, 173, 5)', 'rgb(130, 172, 5)', 'rgb(126, 170, 5)', 'rgb(123, 169, 5)', 'rgb(119, 168, 5)', 'rgb(115, 167, 5)', 'rgb(112, 165, 6)', 'rgb(108, 164, 6)', 'rgb(104, 163, 6)', 'rgb(100, 162, 6)', 'rgb(96, 160, 6)', 'rgb(92, 159, 6)', 'rgb(88, 157, 6)', 'rgb(84, 156, 6)', 'rgb(80, 155, 6)', 'rgb(78, 154, 6)'];
        $opinion = min(100, max(0, intval($note['opinion'])));
        $star_number = floor($opinion / 100 * 5);
        $star_remaining_number = ($opinion / 100 * 5) - floor($opinion / 100 * 5);
        // $color = $opinion > 20 ? ($opinion >= 80 ? '#468847' : '#009edb') : '#b94a48';
        $color = $opinion >= 50 ? '#468847' : '#b94a48';

        ?>
        #note-<?= $note['id'] ?> .star-opinion:nth-last-child(n+<?= 6 - $star_number ?>) {
            color: <?= $color ?>;
        }

        #note-<?= $note['id'] ?> .star-opinion:nth-child(<?= 1 + $star_number ?>)::after {
            font-family: FontAwesome;
            content: "\f005";
            position: absolute;
            left: 0;
            top: 0;
            width: <?= $star_remaining_number * 100 ?>%;
            overflow: hidden;
            color: <?= $color ?>;
        }

        #note-<?= $note['id'] ?> .opinion-gradient-<?= $opinion >= 50 ? 'negative' : 'positive' ?> {
            opacity: 0;
        }
        #note-<?= $note['id'] ?> .opinion-gradient-dot {
            left: calc(<?= $opinion ?>% - 6px);
            /* background-color: <?= $opinion >= 50 ? '#468847' : '#b94a48' ?>; */
            background-color: <?= $opinion_color_scale_100[$opinion] ?>;
        }
        <?php if ($opinion >= 50): ?>
            #note-<?= $note['id'] ?> .opinion-gradient-positive {
                -webkit-mask-image: linear-gradient(90deg, black 0 <?= abs(-50 + $opinion)*2 ?>%, transparent <?= abs(-50 + $opinion)*2 ?>% 100%);
                mask-image: linear-gradient(90deg, black 0 <?= abs(-50 + $opinion)*2 ?>%, transparent <?= abs(-50 + $opinion)*2 ?>% 100%);
            }
        <?php else: ?>
            #note-<?= $note['id'] ?> .opinion-gradient-negative {
                -webkit-mask-image: linear-gradient(90deg, transparent 0 <?= 100-(abs(-50 + $opinion)*2) ?>%, black <?= 100-(abs(-50 + $opinion)*2) ?>% 100%);
                mask-image: linear-gradient(90deg, transparent 0 <?= 100-(abs(-50 + $opinion)*2) ?>%, black <?= 100-(abs(-50 + $opinion)*2) ?>% 100%);
            }
        <?php endif; ?>

        <?php
    }
}

genStyleForOpinionNotes($notes)
?>

</style>