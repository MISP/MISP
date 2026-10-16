// Drag a range over a strip of equal-width buckets laid over a chart.
// The caller decides what a bucket is and what a range means; this only
// turns pointer travel into bucket indices and paints the two masks.
// Markup: genericElementsBS5/brush. Styles: misp-brush.css.
(function () {
    'use strict';

    // Pointer travel, in pixels, under which a drag counts as a click.
    var CLICK_SLOP = 4;

    function stripOf(root) {
        return root.matches && root.matches('[data-misp-brush]')
            ? root
            : root.querySelector('[data-misp-brush]');
    }

    /**
     * Move the masks and the window over the buckets `bounds` covers. A
     * null `bounds` means the selection lies outside the span on screen:
     * everything is dimmed and no window is drawn.
     *
     * @param {Element} root Anything containing the brush's parts
     * @param {{from: number, to: number}|null} bounds Bucket indices
     * @param {number} count How many buckets the chart has
     */
    function paint(root, bounds, count) {
        var strip = stripOf(root);
        if (strip) {
            strip.classList.toggle('misp-brush-empty', bounds === null);
        }
        if (bounds === null) {
            bounds = { from: count, to: count - 1 };
        }
        var left = (100 * bounds.from) / count;
        var right = (100 * (count - 1 - bounds.to)) / count;
        var parts = [
            ['[data-misp-brush-mask-left]', { width: left + '%' }],
            ['[data-misp-brush-mask-right]', { width: right + '%' }],
            ['[data-misp-brush-handle]', {
                left: left + '%',
                right: right + '%',
            }],
        ];
        parts.forEach(function (part) {
            var el = root.querySelector(part[0]);
            if (!el) {
                return;
            }
            Object.keys(part[1]).forEach(function (property) {
                el.style[property] = part[1][property];
            });
        });
    }

    /**
     * No selection at all: no mask and no window. Not the same as
     * `paint(root, null, n)`, which dims everything.
     *
     * @param {Element} root Anything containing the brush's parts
     */
    function clear(root) {
        var strip = stripOf(root);
        if (strip) {
            strip.classList.add('misp-brush-empty');
        }
        ['[data-misp-brush-mask-left]', '[data-misp-brush-mask-right]']
            .forEach(function (selector) {
                var mask = root.querySelector(selector);
                if (mask) {
                    mask.style.width = '0%';
                }
            });
    }

    /**
     * @param {Element|null} strip The layer the drag is read off
     * @param {Object} on `count()` returns how many buckets there are,
     *     asked on every gesture so the caller may rebucket; `range(from,
     *     to)` is called on every pointer move of a real drag; `clear()`
     *     on a click; `settle()` optionally once on release, for work too
     *     expensive to do per move.
     */
    function attach(strip, on) {
        if (!strip) {
            return;
        }
        var anchor = null;
        var origin = 0;
        var moved = false;

        function bucketAt(event) {
            var box = strip.getBoundingClientRect();
            var count = on.count();
            var fraction = (event.clientX - box.left) / box.width;
            var index = Math.floor(fraction * count);
            return Math.max(0, Math.min(count - 1, index));
        }

        strip.addEventListener('pointerdown', function (event) {
            if (on.count() < 1) {
                return;
            }
            anchor = bucketAt(event);
            origin = event.clientX;
            moved = false;
            strip.setPointerCapture(event.pointerId);
            event.preventDefault();
        });

        strip.addEventListener('pointermove', function (event) {
            if (anchor === null) {
                return;
            }
            if (Math.abs(event.clientX - origin) >= CLICK_SLOP) {
                moved = true;
            }
            var to = bucketAt(event);
            on.range(Math.min(anchor, to), Math.max(anchor, to));
        });

        strip.addEventListener('pointerup', function () {
            if (anchor === null) {
                return;
            }
            anchor = null;
            if (!moved) {
                on.clear();
            } else if (on.settle) {
                on.settle();
            }
        });

        strip.addEventListener('pointercancel', function () {
            anchor = null;
        });
    }

    window.MispBrush = { attach: attach, paint: paint, clear: clear };
})();
