function createTagPicker(clicked) {

    function closePicker($select, $container) {
        $select.appendTo($container)
        $container.parent().find('.picker-container').remove()
    }

    function getEditableButtons($select, $container) {
        const $saveButton = $('<button></button>').addClass(['btn btn-primary btn-sm', 'align-self-start']).attr('type', 'button')
        .append($('<span></span>').text('Save').addClass('text-nowrap').prepend($('<i></i>').addClass('fa fa-save me-1')))
        .click(function() {
            const tags = $select.select2('data').map(tag => tag.text)
            addTags($select.data('url'), tags, $(this))
        })
        const $cancelButton = $('<button></button>').addClass(['btn btn-secondary btn-sm', 'align-self-start']).attr('type', 'button')
            .append($('<span></span>').text('Cancel').addClass('text-nowrap').prepend($('<i></i>').addClass('fa fa-times me-1')))
            .click(function() {
                closePicker($select, $container)
            })
        const $buttons = $('<span></span>').addClass(['picker-action', 'btn-group']).append($saveButton, $cancelButton)
        return $buttons
    }

    const $clicked = $(clicked)
    const $container = $clicked.closest('.tag-container')
    const $select = $container.parent().find('select.select2-input').removeClass('d-none')
    closePicker($select, $container)
    const $pickerContainer = $('<div></div>').addClass(['picker-container', 'd-flex'])
    
    $select.prependTo($pickerContainer)
    $pickerContainer.append(getEditableButtons($select, $container))
    $container.parent().append($pickerContainer)
    initSelect2Picker($select)
}

function deleteTag(url, tags, clicked) {
    if (!Array.isArray(tags)) {
        tags = [tags];
    }
    const data = {
        tag_list: JSON.stringify(tags)
    }
    const $statusNode = $(clicked).closest('.tag')
    const APIOptions = {
        statusNode: $statusNode,
        skipFeedback: true,
    }
    return AJAXApi.quickFetchAndPostForm(url, data, APIOptions).then((apiResult) => {
        let $container = $statusNode.closest('.tag-container-wrapper')
        refreshTagList(apiResult, $container).then(($tagContainer) => {
            $container = $tagContainer // old container might not exist anymore since it was replaced after the refresh
        })
        const theToast = UI.toast({
            variant: 'success',
            title: apiResult.message,
            bodyHtml: $('<div/>').append(
                $('<span/>').text('Cancel untag operation.'),
                $('<button/>').addClass(['btn', 'btn-primary', 'btn-sm', 'ms-3']).text('Restore tag').click(function() {
                    const split = url.split('/')
                    const controllerName = split[1]
                    const id = split[3]
                    const urlRetag = `/${controllerName}/tag/${id}`
                    addTags(urlRetag, tags, $container.find('.tag-container')).then(() => {
                        theToast.removeToast()
                    })
                }),
            ),
        })
    }).catch((e) => {})
}

function addTags(url, tags, $statusNode) {
    const data = {
        tag_list: JSON.stringify(tags)
    }
    const APIOptions = {
        statusNode: $statusNode
    }
    return AJAXApi.quickFetchAndPostForm(url, data, APIOptions).then((apiResult) => {
        const $container = $statusNode.closest('.tag-container-wrapper')
        refreshTagList(apiResult, $container)
    }).catch((e) => {})
}

function refreshTagList(apiResult, $container) {
    const controllerName = apiResult.url.split('/')[1]
    const entityId = apiResult.data.id
    const url = `/${controllerName}/viewTags/${entityId}`
    return UI.reload(url, $container)
}

function initSelect2Pickers() {
    $('select.select2-input').each(function() {
        if (!$(this).hasClass("select2-hidden-accessible")) {
            initSelect2Picker($(this))
        }
    })
}

function initSelect2Picker($select) {

    function templateTag(state, $select) {
        if (!state.id) {
            return state.name;
        }
        if (state.colour === undefined) {
            state.colour = $(state.element).data('colour')
        }
        if ($select !== undefined && state.text[0] === '!') {
            // fetch corresponding tag and set colors?
            // const baseTag = state.text.slice(1)
            // const existingBaseTag = $select.find('option').filter(function() {
            //     return $(this).val() === baseTag
            // })
            // if (existingBaseTag.length > 0) {
            //     state.colour = existingBaseTag.data('colour')
            //     state.text = baseTag
            // }
        }
        return buildTag(state)
    }
    const $modal = $select.closest('.modal')

    $select.select2({
        dropdownParent: $modal.length != 0 ? $modal.find('.modal-body') : $(document.body),
        placeholder: 'Pick a tag',
        tags: true,
        width: '100%',
        templateResult: (state) => templateTag(state),
        templateSelection: (state) => templateTag(state, $select),
    })
}

function buildTag(options={}) {
    if (!options.colour) {
        options.colour = '#924da6'
    }
    const $tag = $('<span/>')
        .addClass(['tag', 'badge', 'align-text-top'])
        .css({color: getTextColour(options.colour), 'background-color': options.colour})
        .text(options.text)

    return $tag
}