<?php
    if (empty($textareaClass)) {
        $params['type'] = 'textarea';
        $randomVal = Cake\Utility\Security::randomString(8);
        $textareaClass = "area-for-codemirror-{$randomVal}";
        $params['class'] = [
            $textareaClass
        ];
        echo $this->FormFieldMassage->prepareFormElement($this->Form, $params, $data);
    } else {
        echo sprintf('<textarea class="%s"></textarea>', $textareaClass);
    }
?>

<script>
(function() {
    "use strict";
    const $textArea = $('.<?= $textareaClass ?>')
    const cmDefaultOptions = {
        mode: {
            name: 'javascript',
            json: true
        },
        gutters: ["CodeMirror-lint-markers"],
        lint: true,
        showCursorWhenSelecting: true,
        indentUnit: 4,
        autoCloseBrackets: true,
        matchBrackets: true,
        smartIndent: true,
        lineNumbers: true,
        lineWrapping: true,
        extraKeys: {
            "Ctrl-Space": "autocomplete",
        },
        hintOptions: {
            completeSingle: false,
            hint: jsonHints,
            maxHints: 100
        },
        hintData: {}
    }
    const passedOptions = <?= !empty($data['codemirror']) ? json_encode($data['codemirror']) : '{}' ?>;
    const cmOptions = Object.assign({}, cmDefaultOptions, passedOptions)
    let cm
    init()

    function init() {
        cm = CodeMirror.fromTextArea($textArea[0], cmOptions);
        if (cmOptions['height'] || cmOptions['width']) {
            cm.setSize(
                cmOptions['width'] ? cmOptions['width'] : null,
                cmOptions['height'] ? cmOptions['height'] : null
            )
        }
        if (cmOptions.hints) {
            for (const key in cmOptions.hints) {
                if (Object.hasOwnProperty.call(cmOptions.hints, key)) {
                    const element = cmOptions.hints[key];
                    cmOptions.hintData[key] = element.options ? element.options: null
                }
            }
        }
        cm.on("keyup", function (cm, event) {
            if (!cm.state.completionActive && /*Enables keyboard navigation in autocomplete list*/
                event.keyCode != 13) {     /*Enter - do not open autocomplete list just after item has been selected in it*/ 
                cm.showHint()
            }
            cm.save()
        })
        registerObserver(cm, $textArea[0])
        synchronizeClasses(cm, $textArea[0])
        postInit()
    }

    // Used to synchronize textarea classes (such as `is-invalid` for content validation)
    function registerObserver(cm, textarea) {
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.attributeName == 'class') {
                    synchronizeClasses(cm, textarea)
                }
            });    
        });
        observer.observe(textarea, {attributes: true})
    }

    function postInit() {
        if ($(cm.getInputField()).closest('.modal').length) { // editor is in modal
            setTimeout(() => {
                cm.refresh()
            }, 200); // modal takes 150ms to be displayed
        }
    }

    function synchronizeClasses(cm, textarea) {
        const classes = Array.from(textarea.classList).filter(c => !c.startsWith('area-for-codemirror'))
        const $wrapper = $(cm.getWrapperElement())
        classes.forEach(c => {
            $wrapper.toggleClass(c)
        });
    }

    function jsonHints() {
        const cur = cm.getCursor()
        const token = cm.getTokenAt(cur)
        if (token.type != 'string property' && token.type != 'string') {
            return
        }
        if (cm.getMode().helperType !== "json") {
            return
        }
        token.state = cm.state;
        token.line = cur.line

        if (/\"([^\"]*)\"/.test(token.string)) {
            token.end = cur.ch;
            token.string = token.string.slice(1, cur.ch - token.start);
        }

        return {
            list: getCompletions(token, token.type == 'string property'),
            from: CodeMirror.Pos(cur.line, token.start+1),
            to: CodeMirror.Pos(cur.line, token.end)
        }
    }

    function getCompletions(token, isJSONKey) {
        let hints = []
        if (isJSONKey) {
            hints = findMatchingHints(token.string, Object.keys(cmOptions.hintData))
        } else {
            const jsonKey = findPropertyForValue(token)
            if (cmOptions.hintData[jsonKey]) {
                hints = findMatchingHints(token.string, cmOptions.hintData[jsonKey])
            }
        }
        return hints
    }

    function findMatchingHints(str, hints) {
        hints = hints.map(function(str) {
            var strArray = typeof str === "object" ? String(str.value).split('&quot;') : str.split('&quot;')
            return {
                text: strArray.join('\\\"'), // transforms quoted elements into escaped quote
                displayText: typeof str === "object" ? str.label : strArray.join('\"'),
                render: function(elem, self, data) {
                    $(elem).append(data.displayText);
                }
            }
        })
        if (str.length > 0) {
            let validHints = []
            let hint
            for (let i = 0; validHints.length < cmOptions.hintOptions.maxHints && i < hints.length; i++) {
                if (hints[i].text.startsWith(str)) {
                    validHints.push(hints[i])
                }
            }
            return validHints
        } else {
            return hints.slice(0, cmOptions.hintOptions.maxHints)
        }
    }

    function findPropertyForValue(token) {
        const absoluteIndex = cm.indexFromPos(CodeMirror.Pos(token.line, token.start))
        const rawText = cm.getValue()
        for (let index = absoluteIndex; index > 0; index--) {
            const ch = rawText[index];
            if (ch == ':') {
                const token = cm.getTokenAt(cm.posFromIndex(index-2))
                if (token.type == 'string property') {
                    return token.string.slice(1, token.string.length-1);
                }
            }
        }
        return false
    }
}())
</script>