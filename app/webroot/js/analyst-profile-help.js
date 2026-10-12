/*
 * The "How it works" popovers on the Analyst Profile's Signals pane.
 *
 * One panel, appended to the body so no table cell clips it, filled from
 * the <template> beside the button that opened it. It never scrolls: it
 * takes more columns before it would, then sits over its button, and
 * only then drops examples.
 */
(function () {
    'use strict';

    var LAYOUTS = [['is-two'], ['is-three'], ['is-three', true]];
    var NARROW = [['is-stack'], ['is-stack', true], ['is-two', true]];
    var pop = null;
    var current = null;

    function panel() {
        if (!pop) {
            pop = document.createElement('div');
            pop.className = 'sig-pop';
            pop.id = 'sig-pop';
            pop.setAttribute('role', 'dialog');
            pop.tabIndex = -1;
            pop.hidden = true;
            document.body.appendChild(pop);
        }
        return pop;
    }

    function fillValues() {
        Array.prototype.forEach.call(
            pop.querySelectorAll('[data-ap-help-for]'),
            function (slot) {
                var input = document.getElementById(
                    slot.getAttribute('data-ap-help-for')
                );
                if (!input || input.type === 'checkbox') {
                    return;
                }
                var value = input.value !== '' ? input.value
                    : input.placeholder;
                if (value !== '') {
                    slot.textContent = value;
                }
                slot.classList.toggle('is-edited',
                    input.hasAttribute('data-ap-was')
                    && input.value !== input.getAttribute('data-ap-was'));
            }
        );
    }

    // Below whatever fixed bar covers the top of the window
    function ceiling() {
        pop.style.pointerEvents = 'none';
        var el = document.elementFromPoint(
            document.documentElement.clientWidth / 2, 1
        );
        pop.style.pointerEvents = '';
        for (; el && el !== document.body; el = el.parentElement) {
            var position = getComputedStyle(el).position;
            if (position === 'fixed' || position === 'sticky') {
                return Math.max(8, el.getBoundingClientRect().bottom + 8);
            }
        }
        return 8;
    }

    // A layout is its column class, and whether it takes the full width
    function setLayout(layout) {
        pop.classList.remove('is-stack', 'is-two', 'is-three', 'is-full',
            'c-left');
        pop.classList.add(layout[0]);
        if (layout[1]) {
            pop.classList.add('is-full');
        }
        // Two columns: the examples go under the shorter one
        var a = pop.querySelector('[data-col="a"]');
        var b = pop.querySelector('[data-col="b"]');
        if (layout[0] === 'is-two' && a && b
            && contentHeight(a) < contentHeight(b)) {
            pop.classList.add('c-left');
        }
    }

    // A stretched grid cell is as tall as its row; its content may not be
    function contentHeight(column) {
        var last = column.lastElementChild;
        return last
            ? last.getBoundingClientRect().bottom
                - column.getBoundingClientRect().top
            : 0;
    }

    function untrim() {
        Array.prototype.forEach.call(
            pop.querySelectorAll('[data-ap-trimmed]'),
            function (node) {
                node.hidden = false;
                node.removeAttribute('data-ap-trimmed');
            }
        );
        var more = pop.querySelector('.sig-pop-more');
        if (more) {
            more.remove();
        }
    }

    function trim(room) {
        var hide = function (node) {
            node.hidden = true;
            node.setAttribute('data-ap-trimmed', '');
        };
        var lands = pop.querySelector('.sig-pop-lands');
        if (lands && pop.offsetHeight > room) {
            hide(lands);
        }
        var items = pop.querySelectorAll('.sig-pop-recipes li');
        var hidden = 0;
        for (var i = items.length - 1; i >= 0
            && pop.offsetHeight > room; i--) {
            hide(items[i]);
            hidden++;
        }
        if (hidden > 0) {
            var note = document.createElement('p');
            note.className = 'sig-pop-more';
            note.textContent = hidden + ' '
                + (hidden === 1 ? 'example' : 'examples')
                + ' not shown: make the window taller to read '
                + (hidden === 1 ? 'it' : 'them');
            pop.querySelector('.sig-pop-recipes').after(note);
        }
    }

    function place() {
        var anchor = current;
        var vw = document.documentElement.clientWidth;
        var vh = window.innerHeight;
        var top0 = ceiling();
        var r = anchor.getBoundingClientRect();
        var below = vh - r.bottom - 10;
        var above = r.top - top0 - 6;
        pop.style.left = '0px';
        pop.style.top = '0px';

        var options = (vw < 760 ? NARROW : LAYOUTS).slice();
        var heights = options.map(function (layout) {
            setLayout(layout);
            return pop.offsetHeight;
        });
        // A panel taller than most of the screen reads better wider
        var order = [0, 1, 2];
        if (heights[0] > vh * 0.6 && heights[1] < heights[0]) {
            order = [1, 0, 2];
        }
        var side = 'below';
        var chosen = -1;
        for (var i = 0; i < order.length && chosen < 0; i++) {
            if (heights[order[i]] <= below) {
                chosen = order[i];
            } else if (heights[order[i]] <= above) {
                chosen = order[i];
                side = 'above';
            }
        }
        var height;
        var top;
        if (chosen >= 0) {
            setLayout(options[chosen]);
            height = pop.offsetHeight;
            top = side === 'below' ? r.bottom + 6 : r.top - height - 6;
        } else {
            // Taller than either side: over its button rather than cut short
            var shortest = heights.indexOf(Math.min.apply(null, heights));
            setLayout(options[shortest]);
            trim(vh - top0 - 8);
            height = pop.offsetHeight;
            top = Math.max(top0, Math.min(r.bottom + 6, vh - height - 8));
        }
        var width = pop.offsetWidth;
        var left = Math.min(Math.max(16, r.left - 12), vw - width - 16);
        pop.style.left = Math.max(16, left) + window.scrollX + 'px';
        pop.style.top = top + window.scrollY + 'px';
    }

    function open(button) {
        var template = button.parentNode.querySelector('template.sig-help-tpl');
        if (!template) {
            return;
        }
        close(false);
        panel().innerHTML = '';
        pop.appendChild(template.content.cloneNode(true));
        var body = pop.querySelector('.sig-pop-body');
        if (body && body.getAttribute('aria-labelledby')) {
            pop.setAttribute('aria-labelledby',
                body.getAttribute('aria-labelledby'));
        }
        current = button;
        button.setAttribute('aria-expanded', 'true');
        button.setAttribute('aria-controls', 'sig-pop');
        button.classList.add('is-open');
        fillValues();
        pop.hidden = false;
        place();
        pop.focus({ preventScroll: true });
    }

    function close(restore) {
        if (!current) {
            return;
        }
        var button = current;
        current = null;
        pop.hidden = true;
        pop.innerHTML = '';
        button.setAttribute('aria-expanded', 'false');
        button.classList.remove('is-open');
        if (restore && document.contains(button)) {
            button.focus({ preventScroll: true });
        }
    }

    document.addEventListener('click', function (event) {
        var target = event.target;
        if (!target.closest) {
            return;
        }
        var button = target.closest('[data-ap-help]');
        if (button) {
            event.preventDefault();
            if (button === current) {
                close(true);
            } else {
                open(button);
            }
            return;
        }
        if (target.closest('[data-ap-help-close]')) {
            close(true);
            return;
        }
        if (current && pop && !pop.contains(target)) {
            close(false);
        }
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape' && current) {
            event.stopPropagation();
            close(true);
        }
    }, true);

    document.addEventListener('input', function (event) {
        if (current && event.target.id && pop.querySelector(
            '[data-ap-help-for="' + event.target.id + '"]'
        )) {
            fillValues();
        }
    });

    window.addEventListener('resize', function () {
        if (current) {
            untrim();
            place();
        }
    });
}());
