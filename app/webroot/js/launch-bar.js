/* Filterable action menu of genericElementsBS5/Cards/card_launch_bar. */
(function () {
    'use strict';

    var seq = 0;

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function highlight(label, q) {
        var i = q ? label.toLowerCase().indexOf(q) : -1;
        if (i < 0) {
            return escapeHtml(label);
        }
        return escapeHtml(label.slice(0, i)) + '<mark>' + escapeHtml(label.slice(i, i + q.length)) + '</mark>' +
            escapeHtml(label.slice(i + q.length));
    }

    function init(card) {
        var cmd = card.querySelector('.lb-cmd');
        card.setAttribute('data-launch-bar', 'ready');
        if (!cmd) {
            return;
        }
        var uid = 'lb-' + (++seq);
        var input = cmd.querySelector('.lb-input');
        var menu = cmd.querySelector('.lb-menu');
        var list = cmd.querySelector('.lb-list');
        var empty = cmd.querySelector('.lb-empty');
        var count = cmd.querySelector('.lb-count');
        var items = Array.prototype.slice.call(cmd.querySelectorAll('.lb-item'));
        var groups = Array.prototype.slice.call(cmd.querySelectorAll('.lb-grp'));
        var total = count.textContent;
        var active = null;

        list.id = uid + '-list';
        input.setAttribute('aria-controls', list.id);
        items.forEach(function (item, i) {
            item.id = uid + '-o' + i;
        });

        function visible() {
            return items.filter(function (item) { return !item.hidden; });
        }

        function setActive(item) {
            if (active) {
                active.classList.remove('is-active');
                active.removeAttribute('aria-selected');
            }
            active = item;
            if (!item) {
                input.removeAttribute('aria-activedescendant');
                return;
            }
            item.classList.add('is-active');
            item.setAttribute('aria-selected', 'true');
            input.setAttribute('aria-activedescendant', item.id);
            var box = list.getBoundingClientRect();
            var r = item.getBoundingClientRect();
            if (r.top < box.top) {
                list.scrollTop -= box.top - r.top + 4;
            } else if (r.bottom > box.bottom) {
                list.scrollTop += r.bottom - box.bottom + 4;
            }
        }

        function filter() {
            var q = input.value.trim().toLowerCase();
            items.forEach(function (item) {
                var label = item.getAttribute('data-label');
                item.hidden = q !== '' && label.toLowerCase().indexOf(q) < 0;
                item.querySelector('.lb-lbl').innerHTML = highlight(label, q);
            });
            groups.forEach(function (g) {
                g.hidden = !g.querySelector('.lb-item:not([hidden])');
            });
            var shown = visible();
            empty.hidden = shown.length > 0;
            empty.querySelector('span').textContent = input.value.trim();
            count.textContent = q ? shown.length + ' / ' + items.length : total;
            setActive(q ? shown[0] || null : null);
        }

        function open() {
            if (!menu.hidden) {
                return;
            }
            menu.hidden = false;
            cmd.classList.add('is-open');
            input.setAttribute('aria-expanded', 'true');
            list.scrollTop = 0;
            filter();
        }

        function close(clear) {
            if (menu.hidden) {
                return;
            }
            menu.hidden = true;
            cmd.classList.remove('is-open');
            input.setAttribute('aria-expanded', 'false');
            setActive(null);
            if (clear) {
                input.value = '';
                filter();
            }
        }

        function move(step) {
            var shown = visible();
            if (!shown.length) {
                return;
            }
            var i = shown.indexOf(active);
            setActive(shown[i < 0 ? 0 : Math.max(0, Math.min(shown.length - 1, i + step))]);
        }

        input.addEventListener('focus', open);
        input.addEventListener('click', open);
        input.addEventListener('input', function () {
            open();
            filter();
        });
        input.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (menu.hidden) {
                    open();
                }
                move(1);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                move(-1);
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (active && !menu.hidden) {
                    active.click();
                } else {
                    open();
                }
            } else if (e.key === 'Escape') {
                if (!menu.hidden) {
                    e.preventDefault();
                    e.stopPropagation();
                    if (input.value) {
                        input.value = '';
                        filter();
                    } else {
                        close(false);
                    }
                }
            } else if (e.key === 'Tab') {
                close(false);
            }
        });

        cmd.querySelector('.lb-tog').addEventListener('click', function () {
            if (menu.hidden) {
                input.focus();
            } else {
                close(false);
            }
        });

        items.forEach(function (item) {
            item.addEventListener('mousemove', function () {
                if (active !== item) {
                    setActive(item);
                }
            });
            // Keep focus in the field so the menu does not close mid-click.
            item.addEventListener('mousedown', function (e) {
                e.preventDefault();
            });
            item.addEventListener('click', function () {
                setTimeout(function () {
                    close(true);
                    input.blur();
                }, 0);
            });
        });

        document.addEventListener('mousedown', function (e) {
            if (!cmd.contains(e.target)) {
                close(false);
            }
        });

        // The onboarding tour asks for an anchor that lives in the closed menu.
        cmd.addEventListener('onboarding:reveal', function (e) {
            var item = e.target.closest('.lb-item');
            if (item) {
                open();
                setActive(item);
            }
        });
    }

    function initAll() {
        document.querySelectorAll('[data-launch-bar]:not([data-launch-bar="ready"])').forEach(init);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initAll);
    } else {
        initAll();
    }
})();
