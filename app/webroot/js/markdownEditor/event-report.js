'use strict';

// Function called to setup custom MarkdownIt rendering and parsing rules
var markdownItCustomRules = markdownItSetupRules
// Hint option passed to the CodeMirror constructor
var cmCustomHints = hintMISPElements
// Setup function called after the CodeMirror initialization
var cmCustomSetup = buildMISPElementHints
// Hook allowing to alter the raw text before returning the GFM version to the user to be downloaded
var markdownGFMSubstitution = replaceMISPElementByTheirValue
// Post rendering hook called after the markdown is displayed, allowing to register listener
var markdownCustomPostRenderingListener = setupMISPElementMarkdownListeners
// Post rendering hook called after the markdown is display, allowing to perform any actions on the rendered markdown
var markdownCustomPostRenderingActions = attachRemoteMISPElements
// CodeMirror replacement/insertion actions that can be executed on the editor's text
var customReplacementActions = MISPElementReplacementActions
// Called after CodeMirror initialization to insert custom top bar buttons
var insertCustomToolbarButtons = insertMISPElementToolbarButtons

// Key of the model used by the form when saving
var modelNameForSave = 'EventReport';
// Key of the field used by the form when saving
var markdownModelFieldNameForSave = 'content';

var dotTemplateAttribute = doT.template("<span class=\"misp-element-wrapper attribute useCursorPointer\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\"><span class=\"bold\"><span>{{=it.type}}</span><span class=\"blue\"> {{=it.value}}</span></span></span>");
var dotTemplateAttributePicture = doT.template("<div class=\"misp-picture-wrapper attributePicture useCursorPointer\"><img data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\" href=\"#\" src=\"{{=it.src}}\" alt=\"{{=it.alt}}\" title=\"\"/></div>");
var dotTemplateEventgraph = doT.template("<div class=\"misp-picture-wrapper eventgraphPicture\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\" data-eventid=\"{{=it.eventid}}\"></div>");
var dotTemplateAttackMatrix = doT.template("<div class=\"misp-picture-wrapper embeddedAttackMatrix\" data-scope=\"{{=it.scope}}\" data-eventid=\"{{=it.eventid}}\"></div>");
var dotTemplateObject = doT.template("<span class=\"misp-element-wrapper object useCursorPointer\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\"><span class=\"bold\"><span>{{=it.type}}</span><span class=\"value\">{{=it.value}}</span></span></span>");
var dotTemplateInvalid = doT.template("<span class=\"misp-element-wrapper invalid\"><span class=\"bold red\">{{=it.scope}}<span class=\"blue\"> ({{=it.id}})</span></span></span>");


/**
   _____          _      __  __ _                     
  / ____|        | |    |  \/  (_)                    
 | |     ___   __| | ___| \  / |_ _ __ _ __ ___  _ __ 
 | |    / _ \ / _` |/ _ \ |\/| | | '__| '__/ _ \| '__|
 | |___| (_) | (_| |  __/ |  | | | |  | | | (_) | |   
  \_____\___/ \__,_|\___|_|  |_|_|_|  |_|  \___/|_| 
*/

/* Replacement actions and Toolbar addition */
function MISPElementReplacementActions(action) {
    var start = cm.getCursor('start')
    var end = cm.getCursor('end')
    var content = cm.getRange(start, end)
    var replacement = content
    var setCursorTo = false
    var noMatch = false

    switch (action) {
        case 'element':
            replacement = '@[MISPElement]()'
            end = null
            cm.replaceRange(replacement, start)
            cm.setSelection({line: start.line, ch: start.ch + 2}, {line: start.line, ch: start.ch + 2 + 11})
            cm.focus()
            return true;
        case 'attribute':
            replacement = '@[attribute]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        case 'attribute-attachment':
            replacement = '@![attribute]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        case 'object':
            replacement = '@[object]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        case 'eventgraph':
            replacement = '@[eventgraph]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        default:
            noMatch = true;
            break;
    }
    if (noMatch) {
        return false
    }
    cm.replaceRange(replacement, start, end)
    if (setCursorTo !== false) {
        cm.setCursor(setCursorTo.line, setCursorTo.ch)
    }
    cm.focus()
    return true
}

function insertMISPElementToolbarButtons() {
    insertTopToolbarSection()
    insertTopToolbarButton('cube', 'attribute')
    insertTopToolbarButton('cubes', 'object')
    insertTopToolbarButton('image', 'attribute-attachment')
    insertTopToolbarButton('project-diagram', 'eventgraph')
}

/* Hints */
var MISPElementValues = [], MISPElementTypes = [], MISPElementIDs = []
function buildMISPElementHints() {
    Object.keys(proxyMISPElements['attribute']).forEach(function(k) {
        var attribute = proxyMISPElements['attribute'][k]
        MISPElementValues.push([attribute.value, k])
        MISPElementTypes.push([attribute.type, k])
        MISPElementIDs.push([attribute.id, k])
        MISPElementIDs.push([attribute.uuid, k])
    })
    Object.keys(proxyMISPElements['object']).forEach(function(k) {
        var object = proxyMISPElements['object'][k]
        MISPElementTypes.push([object.name, k])
        MISPElementIDs.push([object.id, k])
        MISPElementIDs.push([object.uuid, k])
    })
}

function hintMISPElements(cm, options) {
    var authorizedMISPElements = ['attribute', 'object']
    var reMISPElement = RegExp('@\\[(?<scope>' + authorizedMISPElements.join('|') + ')\\]\\((?<elementid>[^\\)]+)\\)');
    var reExtendedWord = /\S/
    var scope, elementID, element
    var cursor = cm.getCursor()
    var line = cm.getLine(cursor.line)
    var start = cursor.ch
    var end = cursor.ch
    while (start && reExtendedWord.test(line.charAt(start - 1))) --start
    while (end < line.length && reExtendedWord.test(line.charAt(end))) ++end
    var word = line.slice(start, end).toLowerCase()
    
    var res = reMISPElement.exec(word)
    if (res !== null) {
        scope = res.groups.scope
        elementID = res.groups.elementid
        element = proxyMISPElements[scope][elementID]
        var hintList = []
        if (element !== undefined) {
            hintList.push(
                {
                    text: '@[' + scope + '](' + element.id + ')',
                    render: function(elem, self, data) {
                        var hintElement = renderHintElement(scope, element)
                        $(elem).append(hintElement)
                    },
                    className: 'hint-container',
                }
            )
        } else { // search in hint arrays
            var maxHints = 10
            var MISPElementToCheck = [MISPElementValues, MISPElementTypes, MISPElementIDs]
            MISPElementToCheck.forEach(function(MISPElement) {
                MISPElement.forEach(function(hint) {
                    if (hintList.length >= maxHints) {
                        return false
                    }
                    if (hint[0].startsWith(elementID)) {
                        element = proxyMISPElements[scope][hint[1]]
                        if (element !== undefined) { // Correct scope
                            hintList.push({
                                text: '@[' + scope + '](' + element.id + ')',
                                element: element,
                                render: function(elem, self, data) {
                                    var hintElement = renderHintElement(scope, data.element)
                                    $(elem).append(hintElement)
                                },
                                className: 'hint-container',
                            })
                        }
                    }
                })
            })
        }
        return {
            list: hintList,
            from: CodeMirror.Pos(cursor.line, start),
            to: CodeMirror.Pos(cursor.line, end)
        }
    }
    return null
}

function renderHintElement(scope, element) {
    var $node;
    if (scope == 'attribute') {
        $node = $('<span/>').addClass('hint-attribute')
        $node.append($('<i/>').addClass('').text('[' + element.id + '] '))
            .append($('<span/>').addClass('bold').text(element.type + ' '))
            .append($('<span/>').addClass('bold blue').text(element.value + ' '))
    } else if (scope == 'object') {
        $node = $('<span/>').addClass('hint-object')
        $node.append($('<i/>').addClass('').text('[' + element.id + '] '))
            .append($('<span/>').addClass('bold').text(element.name + ' '))
            .append($('<span/>').addClass('bold blue').text(element.Attribute.length))
    } else {
        $node = $('<span>No match</span>') // should not happen
    }
    return $node
}

/**
  __  __            _       _                     _____ _   
 |  \/  |          | |     | |                   |_   _| |  
 | \  / | __ _ _ __| | ____| | _____      ___ __   | | | |_ 
 | |\/| |/ _` | '__| |/ / _` |/ _ \ \ /\ / / '_ \  | | | __|
 | |  | | (_| | |  |   < (_| | (_) \ V  V /| | | |_| |_| |_ 
 |_|  |_|\__,_|_|  |_|\_\__,_|\___/ \_/\_/ |_| |_|_____|\__|
 */
function markdownItSetupRules() {
    md.renderer.rules.paragraph_open = injectLineNumbers;
    md.renderer.rules.heading_open = injectLineNumbers;
    md.renderer.rules.MISPElement = MISPElementRenderer;
    md.renderer.rules.MISPPictureElement = MISPPictureElementRenderer;
    md.inline.ruler.push('MISP_element_rule', MISPElementRule);
}

/* Parsing Rules */
function MISPElementRule(state, startLine, endLine, silent) {
    var pos, start, labelStart, labelEnd, res, elementID, code, content, token, tokens, attrs, scope
    var oldPos = state.pos,
        max = state.posMax
    
    if (state.src.charCodeAt(state.pos) !== 0x40/* @ */) { return false; }
    if (state.src.charCodeAt(state.pos + 1) === 0x21/* ! */) {
        if (state.src.charCodeAt(state.pos + 2) !== 0x5B/* [ */) { return false;}
    } else {
        if (state.src.charCodeAt(state.pos + 1) !== 0x5B/* [ */) { return false; }
    }

    var isPicture = state.src.charCodeAt(state.pos + 1) === 0x21/* ! */

    if (isPicture) {
        labelStart = state.pos + 3;
        labelEnd = state.md.helpers.parseLinkLabel(state, state.pos + 2, false);
    } else {
        labelStart = state.pos + 2;
        labelEnd = state.md.helpers.parseLinkLabel(state, state.pos + 1, false);
    }

    // parser failed to find ']', so it's not a valid link
    if (labelEnd < 0) { return false; }
    scope = state.src.slice(labelStart, labelEnd)

    pos = labelEnd + 1;
    if (pos < max && state.src.charCodeAt(pos) === 0x28/* ( */) {
        start = pos;
        res = state.md.helpers.parseLinkDestination(state.src, pos, state.posMax);
        if (res.ok) {
            // parseLinkDestination does not support trailing characters such as `.` after the link
            // so we have to find the matching `)`
            var destinationEnd = res.str.length - 1
            var traillingCharNumber = 0
            for (var i = res.str.length-1; i > 1; i--) {
                var code = res.str.charCodeAt(i)
                if (code === 0x29 /* ) */) {
                    destinationEnd = i
                    break
                }
                traillingCharNumber++
            }
            elementID = res.str.substring(1, destinationEnd);
            pos = res.pos - 1 - traillingCharNumber;
        }
    }

    if (pos >= max || state.src.charCodeAt(pos) !== 0x29/* ) */) {
        state.pos = oldPos;
        return false;
    }
    pos++;

    if (!/^\d+$/.test(elementID)) {
        return false;
    }

    // We found the end of the link, and know for a fact it's a valid link;
    // so all that's left to do is to call tokenizer.
    content = {
        scope: scope,
        elementID: elementID,
    }

    if (isPicture) {
        token      = state.push('MISPPictureElement', 'div', 0);
    } else {
        token      = state.push('MISPElement', 'div', 0);
    }
    token.children = tokens;
    token.content  = content;

    state.pos = pos;
    state.posMax = max;
    return true;
}

/* Rendering rules */
function MISPElementRenderer(tokens, idx, options, env, slf) {
    var allowedScope = ['attribute', 'object', 'eventgraph', 'attackmatrix']
    var token = tokens[idx];
    var scope = token.content.scope
    var elementID = token.content.elementID
    if (allowedScope.indexOf(scope) == -1) {
        return renderInvalidMISPElement(scope, elementID);
    }
    return renderMISPElement(scope, elementID)
}

function MISPPictureElementRenderer(tokens, idx, options, env, slf) {
    var allowedScope = ['attribute']
    var token = tokens[idx];
    var scope = token.content.scope
    var elementID = token.content.elementID
    if (allowedScope.indexOf(scope) == -1) {
        return renderInvalidMISPElement(scope, elementID);
    }
    return renderMISPPictureElement(scope, elementID)
}

function renderMISPElement(scope, elementID) {
    var templateVariables
    if (scope == 'attribute') {
        var attribute = proxyMISPElements[scope][elementID]
        if (attribute !== undefined) {
            templateVariables = sanitizeObject({
                scope: 'attribute',
                elementid: elementID,
                type: attribute.type,
                value: attribute.value
            })
            return dotTemplateAttribute(templateVariables);
        }
    } else if (scope == 'object') {
        var mispObject = proxyMISPElements[scope][elementID]
        if (mispObject !== undefined) {
            var associatedTemplate = mispObject.template_uuid + '.' + mispObject.template_version
            var objectTemplate = proxyMISPElements['objectTemplates'][associatedTemplate]
            var topPriorityValue = mispObject.Attribute.length
            if (objectTemplate !== undefined) {
                var temp = getPriorityValue(mispObject, objectTemplate)
                topPriorityValue = temp !== false ? temp : topPriorityValue
            }
            templateVariables = sanitizeObject({
                scope: 'object',
                elementid: elementID,
                type: mispObject.name,
                value: topPriorityValue
            })
            return dotTemplateObject(templateVariables);
        }
    } else if (scope == 'eventgraph') {
        return dotTemplateEventgraph({scope: 'eventgraph', elementid: elementID, eventid: eventid});
    } else if (scope == 'attackmatrix') {
        return dotTemplateAttackMatrix({scope: 'attackmatrix', eventid: eventid});
    }
    return renderInvalidMISPElement(scope, elementID)
}

function renderMISPPictureElement(scope, elementID) {
    var attribute = proxyMISPElements[scope][elementID]
    if (attribute !== undefined) {
        var templateVariables = sanitizeObject({
            scope: 'attribute',
            elementid: elementID,
            type: attribute.type,
            value: attribute.value,
            alt: scope + ' ' + elementID,
            src: baseurl + '/attributes/viewPicture/' + attribute.id,
            title: attribute.type + ' ' + attribute.value,
        })
        return dotTemplateAttributePicture(templateVariables);
    }
    return renderInvalidMISPElement(scope, elementID)
}

function renderInvalidMISPElement(scope, elementID) {
    var templateVariables = sanitizeObject({
        scope: invalidMessage,
        id: elementID
    })
    return dotTemplateInvalid(templateVariables);
}

function setupMISPElementMarkdownListeners() {
    $('.misp-element-wrapper').filter('.attribute').popover({
        trigger: 'click',
        html: true,
        container: 'body',
        placement: 'top',
        title: getTitleFromMISPElementDOM,
        content: getContentFromMISPElementDOM
    })
    $('.misp-picture-wrapper > img').popover({
        trigger: 'click',
        html: true,
        container: 'body',
        placement: 'top',
        title: getTitleFromMISPElementDOM,
        content: getContentFromMISPElementDOM,
        placement: 'top'
    })
    $('.misp-element-wrapper').filter('.object').popover({
        trigger: 'click',
        html: true,
        container: 'body',
        placement: 'top',
        title: getTitleFromMISPElementDOM,
        content: getContentFromMISPElementDOM
    })
}

function attachRemoteMISPElements() {
    $('.eventgraphPicture[data-scope="eventgraph"]').each(function() {
        var $div = $(this)
        clearTimeout(eventgraphTimer);
        $div.append($('<div/>').css('font-size', '24px').append(loadingSpanAnimation))
        if (cache_eventgraph[$div.data('elementid')] === undefined) {
            eventgraphTimer = setTimeout(function() {
                attachEventgraphPicture($div, $div.data('eventid'), $div.data('elementid'))
            }, slowDebounceDelay);
        } else {
            $div.html(cache_eventgraph[$div.data('elementid')])
        }
    })
    $('.embeddedAttackMatrix[data-scope="attackmatrix"]').each(function() {
        var $div = $(this)
        clearTimeout(attackMatrixTimer);
        $div.append($('<div/>').css('font-size', '24px').append(loadingSpanAnimation))
        if (cache_matrix[eventid] === undefined) {
            attackMatrixTimer = setTimeout(function() {
                attachAttackMatrix($div, $div.data('eventid'))
            }, slowDebounceDelay);
        } else {
            $div.html(cache_matrix[eventid])
        }
    })
}

function attachEventgraphPicture($elem, eventID, graphID) {
    $.getJSON(baseurl + '/eventGraph/view/' + eventID + '/' + graphID, function (data) {
        if (data && data.length > 0) {
            var dataPicture = data[0]['EventGraph']['preview_img']
            if (dataPicture !== undefined) {
                $elem.empty().append($('<img />').attr('src', dataPicture))
                cache_eventgraph[graphID] = $elem.find('img')[0].outerHTML;
                return
            }
        }
        var templateVariables = sanitizeObject({
            scope: 'Error while fetching saved Event Graph picture',
            id: graphID
        })
        var placeholder = dotTemplateInvalid(templateVariables)
        $elem.empty()
            .css({'text-align': 'center'})
            .append($(placeholder))
        cache_eventgraph[graphID] = $elem.children()[0].outerHTML;
    })
}

function attachAttackMatrix($elem, eventid) {
    $.ajax({
        data: {
            "returnFormat": "attack",
            "eventid": eventid
        },
        success:function(data, textStatus) {
            $elem.empty().append($(data))
            $elem.find('#attackmatrix_div').css({
                'max-width': 'unset',
                'min-width': 'unset',
                'width': 'calc(100% - 5px)'
            })
            $elem.find('#checkbox_attackMatrix_showAll').click()
            $elem.find('#attackmatrix_div .heatCell').each(function() {
                if ($(this).css('background-color').length > 0 && $(this).css('background-color') != 'rgba(0, 0, 0, 0)') {
                    $(this).attr('style', 'background-color:' + $(this).css('background-color') + ' !important; color:' + $(this).css('color') + ' !important;');
                }
            })
            cache_matrix[eventid] = $elem.find('#attackmatrix_div')[0].outerHTML;
        },
        error: function(jqXHR, textStatus, errorThrown) {
            var templateVariables = sanitizeObject({
                scope: 'Error while fetching matrix',
                id: graphID
            })
            var placeholder = dotTemplateInvalid(templateVariables)
            $elem.empty()
                .css({'text-align': 'center'})
                .append($(placeholder))
        },
        type:"post",
        url: baseurl + "/events/restSearch"
    })
}


/**
   _____             _             
  / ____|           (_)            
 | (___   __ ___   ___ _ __   __ _ 
  \___ \ / _` \ \ / / | '_ \ / _` |
  ____) | (_| |\ V /| | | | | (_| |
 |_____/ \__,_| \_/ |_|_| |_|\__, |
                              __/ |
                             |___/
*/
function replaceMISPElementByTheirValue(raw) {
    var match, replacement, element
    var final = ''
    var authorizedMISPElements = ['attribute', 'object']
    var reMISPElement = RegExp('@\\[(?<scope>' + authorizedMISPElements.join('|') + ')\\]\\((?<elementid>[\\d]+)\\)', 'g');
    var offset = 0
    while ((match = reMISPElement.exec(raw)) !== null) {
        element = proxyMISPElements[match.groups.scope][match.groups.elementid]
        if (element !== undefined) {
            replacement = match.groups.scope + '-' + element.uuid
        } else {
            replacement = match.groups.scope + '-' + match.groups.elementid
        }
        final += raw.substring(offset, match.index) + replacement
        offset = reMISPElement.lastIndex
    }
    final += raw.substring(offset)
    return final
}


/**
  _    _ _   _ _     
 | |  | | | (_) |    
 | |  | | |_ _| |___ 
 | |  | | __| | / __|
 | |__| | |_| | \__ \
  \____/ \__|_|_|___/
*/
function getElementFromDom(node) {
    var scope = $(node).data('scope')
    var elementID = $(node).data('elementid')
    if (scope !== undefined && elementID !== undefined) {
        return {
            element: proxyMISPElements[scope][elementID],
            scope: scope,
            elementID: elementID
        }
    }
    return false
}

function getTitleFromMISPElementDOM() {
    var data = getElementFromDom(this)
    var title = invalidMessage
    var dismissButton = ''
    if (data !== false) {
        dismissButton = '<button type="button" class="close" style="margin-left: 5px;" data-scope="' + data.scope + '" data-elementid="' + data.elementID + '" onclick="closeThePopover(this)">×</button>';
        title = data.scope.charAt(0).toUpperCase() + data.scope.slice(1) + ' ' + data.elementID
    }
    return title + dismissButton
}


function closeThePopover(closeButton) {
    var scope = $(closeButton).data('scope')
    var elementID = $(closeButton).data('elementid')
    var $MISPElement = $('[data-scope="' + scope + '"][data-elementid="' + elementID + '"]')
    $MISPElement.popover('hide');
}

function constructAttributeRow(attribute)
{
    var attributeFieldsToRender = ['id', 'category', 'type', 'value', 'comment']
    var $tr = $('<tr/>')
    attributeFieldsToRender.forEach(function(field) {
        $tr.append(
            $('<td/>').text(attribute[field])
                .css('white-space', ['id', 'type'].indexOf(field) != -1 ? 'nowrap' : 'none')
        )
    })
    var $tags = $('<div/>')
    if (attribute.AttributeTag !== undefined) {
        attribute.AttributeTag.forEach(function(attributeTag) {
            var tag = attributeTag.Tag
            var $tag = $('<div/>').append(
                $('<span/>')
                    .addClass('tagComplete nowrap')
                    .css({'background-color': tag.colour, 'color': getTextColour(tag.colour), 'box-shadow': '1px 1px 3px #888888c4'})
                    .text(tag.name)
            )
            $tags.append($tag)
        })
    }
    $tr.append($('<td/>').append($tags))
    var $galaxies = $('<div/>')
    if (attribute.Galaxy !== undefined) {
        attribute.Galaxy.forEach(function(galaxy) {
            var $galaxy = $('<div/>').append(
                $('<span/>')
                    .addClass('tagComplete nowrap')
                    .css({'background-color': '#0088cc', 'color': getTextColour('#0088cc'), 'box-shadow': '1px 1px 3px #888888c4'})
                    .text(galaxy.name + ' :: ' + galaxy.GalaxyCluster[0].value)
            )
            $galaxies.append($galaxy)
        })
    }
    $tr.append($('<td/>').append($galaxies))
    return $tr
}

function constructAttributeHeader(attribute, showAll) {
    showAll = showAll !== undefined ? showAll : false
    var attributeFieldsToRender = ['id', 'category', 'type', 'value', 'comment']
    var $tr = $('<tr/>')
    attributeFieldsToRender.forEach(function(field) {
        $tr.append($('<th/>').text(field))
    })
    if (showAll || (attribute.AttributeTag !== undefined && attribute.AttributeTag.length > 0)) {
        $tr.append($('<th/>').text('tags'))
    }
    if (showAll || (attribute.Galaxy !== undefined && attribute.Galaxy.length > 0)) {
        $tr.append($('<th/>').text('galaxies'))
    }
    var $thead = $('<thead/>').append($tr)
    return $thead
}

function constructObject(object) {
    var objectFieldsToRender = ['id', 'name', 'description', 'distribution']
    var $object = $('<div/>').addClass('similarObjectPanel')
                    .css({border: '1px solid #3465a4', 'border-radius': '5px'})
    var $top = $('<div/>').addClass('blueElement')
        .css({padding: '4px 5px'})
    objectFieldsToRender.forEach(function(field) {
        $top.append($('<div/>').append(
            $('<span/>').addClass('bold').text(field + ': '),
            $('<span/>').text(object[field])
        ))
    })
    
    var $attributeTable = $('<table/>').addClass('table table-striped table-condensed')
        .css({'margin-bottom': '3px'})
    var $thead = constructAttributeHeader({}, true)
    var $tbody = $('<tbody/>')
    object.Attribute.forEach(function(attribute) {
        $tbody.append(constructAttributeRow(attribute))
    })
    $attributeTable.append($thead, $tbody)
    $object.append($top, $attributeTable)
    return $('<div/>').append($object)
}

function getPriorityValue(mispObject, objectTemplate) {
    for (var i = 0; i < objectTemplate.ObjectTemplateElement.length; i++) {
        var object_relation = objectTemplate.ObjectTemplateElement[i].object_relation;
        for (var j = 0; j < mispObject.Attribute.length; j++) {
            var attribute = mispObject.Attribute[j];
            if (attribute.object_relation === object_relation) {
                return attribute.value
            }
        }
    }
    return false
}

function getContentFromMISPElementDOM() {
    var data = getElementFromDom(this)
    
    if (data !== false) {
        if (data.scope == 'attribute') {
            var $thead = constructAttributeHeader(data.element)
            var $row = constructAttributeRow(data.element)
            var $attribute = $('<div/>').append(
                $('<table/>')
                    .addClass('table table-condensed')
                    .append($thead)
                    .append($('<tbody/>').append($row))
            )
            return $attribute.html()
        } else if (data.scope == 'object') {
            var $object = constructObject(data.element)
            return $object.html()
        }
    }
    return invalidMessage
}