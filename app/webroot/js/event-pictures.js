/*
 * Event pictures: a slideshow of the event's image attachments, and the
 * full-screen viewer it opens.
 *
 *   EventPictures.mount(cardEl, pictures, {strings, distributions})
 *
 * pictures: [{id, filename, comment, category, object: {name}|null,
 *             distribution, timestamp, src, thumb, download, attributeUrl}]
 * The pixel size is read off the picture once it has loaded.
 */
(function () {
    'use strict';

    function h(tag, cls, attrs) {
        var node = document.createElement(tag);
        if (cls) { node.className = cls; }
        if (attrs) {
            Object.keys(attrs).forEach(function (k) {
                if (k === 'text') { node.textContent = attrs[k]; }
                else { node.setAttribute(k, attrs[k]); }
            });
        }
        return node;
    }

    function icon(cls) {
        return h('i', cls, { 'aria-hidden': 'true' });
    }

    function fmt(str) {
        var args = Array.prototype.slice.call(arguments, 1);
        var i = 0;
        return str.replace(/%s/g, function () { return args[i++]; });
    }

    function pad(n) { return n < 10 ? '0' + n : '' + n; }

    function when(ts) {
        var d = new Date(ts * 1000);
        return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
            + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
    }

    function dims(p) {
        return p.width && p.height ? p.width + ' × ' + p.height : '';
    }

    function titleOf(p) {
        return p.comment || p.filename;
    }

    // Record the size the first time the picture is seen; true when it was new.
    function learnSize(p, img) {
        if (p.width || !img.naturalWidth) { return false; }
        p.width = img.naturalWidth;
        p.height = img.naturalHeight;
        return true;
    }

    // Keep the active thumb in view without moving the page.
    function centreIn(strip, thumb, smooth) {
        var left = thumb.offsetLeft - (strip.clientWidth - thumb.offsetWidth) / 2;
        strip.scrollTo({ left: Math.max(0, left), behavior: smooth ? 'smooth' : 'auto' });
    }

    function edgeFade(strip) {
        function update() {
            var max = strip.scrollWidth - strip.clientWidth;
            strip.classList.toggle('fade-l', strip.scrollLeft > 2);
            strip.classList.toggle('fade-r', strip.scrollLeft < max - 2);
        }
        strip.addEventListener('scroll', update, { passive: true });
        window.addEventListener('resize', update);
        update();
        return update;
    }

    function buildStrip(pictures, cls, label, onPick) {
        var strip = h('div', cls, { role: 'tablist', 'aria-label': label });
        var thumbs = pictures.map(function (p, i) {
            var b = h('button', 'ep-thumb', {
                type: 'button',
                role: 'tab',
                'aria-label': titleOf(p),
                title: titleOf(p),
                tabindex: '-1',
            });
            var img = h('img', null, { src: p.thumb, alt: '', loading: 'lazy', decoding: 'async' });
            b.appendChild(img);
            b.addEventListener('click', function () { onPick(i); });
            strip.appendChild(b);
            return b;
        });
        // One tab stop for the strip; arrows walk it.
        strip.addEventListener('keydown', function (e) {
            var i = thumbs.indexOf(document.activeElement);
            if (i < 0) { return; }
            var next = null;
            if (e.key === 'ArrowRight') { next = (i + 1) % thumbs.length; }
            if (e.key === 'ArrowLeft') { next = (i - 1 + thumbs.length) % thumbs.length; }
            if (e.key === 'Home') { next = 0; }
            if (e.key === 'End') { next = thumbs.length - 1; }
            if (next === null) { return; }
            e.preventDefault();
            e.stopPropagation();
            onPick(next);
            thumbs[next].focus();
        });
        return {
            el: strip,
            select: function (i, smooth) {
                thumbs.forEach(function (t, j) {
                    t.setAttribute('aria-current', j === i ? 'true' : 'false');
                    t.setAttribute('aria-selected', j === i ? 'true' : 'false');
                    t.tabIndex = j === i ? 0 : -1;
                });
                centreIn(strip, thumbs[i], smooth);
            }
        };
    }

    /* ------------------------------------------------------------------ */
    /* Viewer                                                              */
    /* ------------------------------------------------------------------ */

    function Viewer(pictures, opts) {
        var t = opts.strings;
        var dist = opts.distributions || {};
        var n = pictures.length;
        var index = 0;
        var actual = false;
        var returnFocus = null;
        var self = this;

        var root = h('div', 'ep-lb', {
            role: 'dialog',
            'aria-modal': 'true',
            'aria-label': t.viewerLabel,
            hidden: '',
        });

        var top = h('div', 'ep-lb-top');
        var count = h('span', 'ep-lb-count');
        var title = h('div', 'ep-lb-title');
        var actions = h('div', 'ep-lb-actions');
        var actualBtn = h('button', 'ep-lb-btn', { type: 'button', 'aria-pressed': 'false', title: t.actualSizeHint });
        actualBtn.appendChild(icon('fas fa-magnifying-glass-plus'));
        var actualLabel = h('span', null, { text: t.actualSize });
        actualBtn.appendChild(actualLabel);
        var dl = h('a', 'ep-lb-btn', { title: t.download });
        dl.appendChild(icon('fas fa-download'));
        dl.appendChild(h('span', null, { text: t.download }));
        var attr = h('a', 'ep-lb-btn', { title: t.attributeHint });
        attr.appendChild(icon('misp-icon misp-icon-attribute misp-simple'));
        attr.appendChild(h('span', null, { text: t.attribute }));
        var close = h('button', 'ep-lb-btn ep-lb-close', { type: 'button', 'aria-label': t.close, title: t.close + ' (Esc)' });
        close.appendChild(icon('fas fa-xmark'));
        actions.append(actualBtn, dl, attr, close);
        top.append(count, title, actions);

        var view = h('div', 'ep-lb-view');
        var pan = h('div', 'ep-lb-pan');
        var inner = h('div', 'ep-lb-inner');
        var img = h('img', 'ep-lb-img', { alt: '', draggable: 'false' });
        inner.appendChild(img);
        pan.appendChild(inner);
        view.appendChild(pan);
        var prev = null, next = null;
        if (n > 1) {
            prev = h('button', 'ep-lb-nav ep-lb-prev', { type: 'button', 'aria-label': t.previous, title: t.previous });
            prev.appendChild(icon('fas fa-chevron-left'));
            next = h('button', 'ep-lb-nav ep-lb-next', { type: 'button', 'aria-label': t.next, title: t.next });
            next.appendChild(icon('fas fa-chevron-right'));
            view.append(prev, next);
        }

        var foot = h('div', 'ep-lb-foot');
        var meta = h('div', 'ep-lb-meta', { 'aria-live': 'polite' });
        foot.appendChild(meta);
        var strip = null;
        if (n > 1) {
            strip = buildStrip(pictures, 'ep-lb-strip', t.strip, function (i) { self.show(i); });
            foot.appendChild(strip.el);
            var keys = h('div', 'ep-lb-keys');
            keys.innerHTML = '';
            keys.append(h('kbd', null, { text: '←' }), ' ', h('kbd', null, { text: '→' }),
                ' ' + t.keysBrowse + ' · ', h('kbd', null, { text: 'Esc' }), ' ' + t.keysClose);
            foot.appendChild(keys);
        }

        root.append(top, view, foot);
        document.body.appendChild(root);

        function fitScale() {
            if (!img.naturalWidth) { return 1; }
            return Math.min(1, img.clientWidth / img.naturalWidth);
        }

        function zoomable() {
            return !actual && img.naturalWidth > 0 && fitScale() < 0.98;
        }

        function syncZoom() {
            var canZoom = actual || zoomable();
            actualBtn.disabled = !canZoom;
            actualBtn.setAttribute('aria-pressed', actual ? 'true' : 'false');
            actualLabel.textContent = actual ? t.fit : t.actualSize;
            actualBtn.firstChild.className = actual ? 'fas fa-magnifying-glass-minus' : 'fas fa-magnifying-glass-plus';
            img.classList.toggle('is-zoomable', !actual && canZoom);
        }

        function setActual(on, fx, fy) {
            if (on && !zoomable()) { return; }
            actual = on;
            root.classList.toggle('is-actual', on);
            if (on) {
                var cx = fx === undefined ? 0.5 : fx;
                var cy = fy === undefined ? 0.5 : fy;
                pan.scrollLeft = Math.max(0, inner.scrollWidth * cx - pan.clientWidth / 2);
                pan.scrollTop = Math.max(0, inner.scrollHeight * cy - pan.clientHeight / 2);
            }
            syncZoom();
        }

        function renderMeta(p) {
            meta.replaceChildren();
            if (p.comment) {
                var f = h('span', 'ep-lb-file');
                f.appendChild(icon('fas fa-file-image'));
                f.appendChild(document.createTextNode(p.filename));
                meta.appendChild(f);
            }
            if (p.object) {
                var o = h('span');
                o.appendChild(icon('misp-icon misp-icon-object misp-simple'));
                o.appendChild(document.createTextNode(fmt(t.inObject, p.object.name)));
                meta.appendChild(o);
            }
            meta.appendChild(h('span', null, { text: p.category }));
            if (dims(p)) { meta.appendChild(h('span', null, { text: dims(p) })); }
            var d = dist[p.distribution];
            if (d) {
                var ds = h('span');
                ds.appendChild(icon(d.icon));
                ds.appendChild(document.createTextNode(d.label));
                meta.appendChild(ds);
            }
            meta.appendChild(h('span', null, { text: when(p.timestamp) }));
        }

        this.show = function (i) {
            index = (i + n) % n;
            var p = pictures[index];
            if (actual) { setActual(false); }
            count.textContent = n > 1 ? fmt(t.counter, index + 1, n) : '';
            title.textContent = titleOf(p);
            title.title = titleOf(p);
            dl.href = p.download;
            attr.href = p.attributeUrl;
            img.alt = titleOf(p);
            img.style.opacity = '0';
            img.onload = function () {
                img.style.opacity = '1';
                if (learnSize(p, img)) { renderMeta(p); }
                syncZoom();
            };
            img.src = p.src;
            if (img.complete && img.naturalWidth) { img.onload(); }
            renderMeta(p);
            if (strip) { strip.select(index, root.classList.contains('is-open')); }
            if (opts.onChange) { opts.onChange(index); }
        };

        this.open = function (i, from) {
            returnFocus = from || document.activeElement;
            root.hidden = false;
            document.documentElement.style.overflow = 'hidden';
            this.show(i);
            requestAnimationFrame(function () {
                root.classList.add('is-open');
                close.focus();
                if (strip) { strip.select(index, false); }
            });
            document.addEventListener('keydown', onKey, true);
        };

        this.close = function () {
            root.classList.remove('is-open');
            setActual(false);
            document.documentElement.style.overflow = '';
            document.removeEventListener('keydown', onKey, true);
            setTimeout(function () { root.hidden = true; }, 180);
            if (returnFocus && returnFocus.focus) { returnFocus.focus({ preventScroll: true }); }
        };

        this.isOpen = function () { return !root.hidden; };
        this.destroy = function () {
            if (!root.hidden) { self.close(); }
            window.removeEventListener('resize', onResize);
            root.remove();
        };
        this.root = root;
        this.toggleActual = function () { setActual(!actual); };

        function onKey(e) {
            if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                if (actual) { setActual(false); } else { self.close(); }
                return;
            }
            if (e.key === 'ArrowLeft' && n > 1 && !e.target.closest('.ep-lb-strip')) {
                e.preventDefault(); self.show(index - 1);
            } else if (e.key === 'ArrowRight' && n > 1 && !e.target.closest('.ep-lb-strip')) {
                e.preventDefault(); self.show(index + 1);
            } else if (e.key === 'Tab') {
                var f = Array.prototype.filter.call(
                    root.querySelectorAll('button:not([disabled]), a[href], [tabindex="0"]'),
                    function (x) { return x.offsetParent !== null; }
                );
                if (!f.length) { return; }
                var first = f[0], last = f[f.length - 1];
                if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
                else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
        }

        close.addEventListener('click', function () { self.close(); });
        actualBtn.addEventListener('click', function () { setActual(!actual); });
        if (prev) {
            prev.addEventListener('click', function () { self.show(index - 1); });
            next.addEventListener('click', function () { self.show(index + 1); });
        }

        // Fit: click the picture for actual size there, click around it to close.
        // Actual: drag to pan, click without dragging to fit again.
        var drag = null;
        pan.addEventListener('pointerdown', function (e) {
            if (e.button !== 0) { return; }
            drag = { x: e.clientX, y: e.clientY, sl: pan.scrollLeft, st: pan.scrollTop, moved: false };
            if (actual) { pan.setPointerCapture(e.pointerId); }
        });
        pan.addEventListener('pointermove', function (e) {
            if (!drag || !actual) { return; }
            var dx = e.clientX - drag.x, dy = e.clientY - drag.y;
            if (Math.abs(dx) + Math.abs(dy) > 3) { drag.moved = true; pan.classList.add('is-dragging'); }
            pan.scrollLeft = drag.sl - dx;
            pan.scrollTop = drag.st - dy;
        });
        pan.addEventListener('pointerup', function (e) {
            if (!drag) { return; }
            var d = drag;
            drag = null;
            pan.classList.remove('is-dragging');
            if (d.moved) { return; }
            if (actual) { setActual(false); return; }
            if (e.target === img) {
                var r = img.getBoundingClientRect();
                setActual(true, (e.clientX - r.left) / r.width, (e.clientY - r.top) / r.height);
            } else {
                self.close();
            }
        });
        function onResize() { if (!root.hidden) { syncZoom(); } }
        window.addEventListener('resize', onResize);
    }

    /* ------------------------------------------------------------------ */
    /* Rail card                                                           */
    /* ------------------------------------------------------------------ */

    function mount(card, pictures, opts) {
        var t = opts.strings;
        var n = pictures.length;
        var index = 0;
        var front = 0;
        var seq = 0;
        var viewer = null;

        if (card.epInstance) { card.epInstance.destroy(); }
        card.epInstance = null;
        if (!n) {
            card.hidden = true;
            return null;
        }
        card.hidden = false;

        var sub = card.querySelector('[data-ep-sub]');
        if (sub) { sub.textContent = n === 1 ? t.one : fmt(t.many, n); }

        var body = card.querySelector('[data-ep-body]');
        body.replaceChildren();

        var stage = h('div', 'ep-stage' + (n === 1 ? ' is-single' : ''), {
            tabindex: '0',
            role: 'group',
            'aria-roledescription': t.carousel,
            'aria-label': t.carouselLabel,
        });
        var backdrops = [h('div', 'ep-backdrop'), h('div', 'ep-backdrop')];
        var slides = [0, 1].map(function () {
            var s = h('div', 'ep-slide', { 'aria-hidden': 'true' });
            var img = h('img', null, { alt: '', decoding: 'async' });
            s.appendChild(img);
            return { el: s, img: img };
        });
        stage.append(backdrops[0], backdrops[1], slides[0].el, slides[1].el);

        var counter = null;
        if (n > 1) {
            counter = h('span', 'ep-chip ep-counter');
            var prev = h('button', 'ep-nav ep-prev', { type: 'button', 'aria-label': t.previous, title: t.previous });
            prev.appendChild(icon('fas fa-chevron-left'));
            var next = h('button', 'ep-nav ep-next', { type: 'button', 'aria-label': t.next, title: t.next });
            next.appendChild(icon('fas fa-chevron-right'));
            prev.addEventListener('click', function (e) { e.stopPropagation(); show(index - 1); });
            next.addEventListener('click', function (e) { e.stopPropagation(); show(index + 1); });
            stage.append(counter, prev, next);
        }
        var hint = h('span', 'ep-chip ep-zoom-hint');
        hint.appendChild(icon('fas fa-expand'));
        hint.appendChild(document.createTextNode(t.enlarge));
        stage.appendChild(hint);

        var caption = h('div', 'ep-caption', { 'aria-live': 'polite' });
        var capTitle = h('div', 'ep-cap-title');
        var capMeta = h('div', 'ep-cap-meta');
        caption.append(capTitle, capMeta);

        body.append(stage, caption);

        var strip = null;
        if (n > 1) {
            strip = buildStrip(pictures, 'ep-strip', t.strip, function (i) { show(i); });
            body.appendChild(strip.el);
            edgeFade(strip.el);
        }

        function renderCaption(p) {
            capTitle.textContent = titleOf(p);
            capTitle.title = titleOf(p);
            capMeta.replaceChildren();
            if (p.object) {
                var o = h('span', 'ep-obj', { title: fmt(t.inObject, p.object.name) });
                o.appendChild(icon('misp-icon misp-icon-object misp-simple'));
                o.appendChild(document.createTextNode(p.object.name));
                capMeta.appendChild(o);
            }
            var text = p.comment ? p.filename : p.category;
            capMeta.appendChild(h('span', 'ep-cap-text', { text: text, title: text }));
            if (dims(p)) { capMeta.appendChild(h('span', 'ep-cap-dims', { text: dims(p) })); }
        }

        function show(i, instant) {
            index = (i + n) % n;
            var p = pictures[index];
            var token = ++seq;
            var back = front ^ 1;
            var layer = slides[back];
            var swapped = false;
            // A cached picture is complete at once and still fires load later.
            var swap = function () {
                if (swapped || token !== seq) { return; }
                swapped = true;
                if (learnSize(p, layer.img)) { renderCaption(p); }
                slides[back].el.classList.add('is-on');
                slides[front].el.classList.remove('is-on');
                backdrops[back].style.backgroundImage = 'url("' + p.thumb + '")';
                backdrops[back].classList.add('is-on');
                backdrops[front].classList.remove('is-on');
                front = back;
            };
            layer.img.onload = swap;
            layer.img.onerror = swap;
            layer.img.alt = titleOf(p);
            layer.img.src = p.src;
            if (layer.img.complete && layer.img.naturalWidth) { swap(); }

            stage.setAttribute('aria-label', fmt(t.slideLabel, index + 1, n, titleOf(p)));
            if (counter) { counter.textContent = fmt(t.counter, index + 1, n); }
            renderCaption(p);
            if (strip) { strip.select(index, !instant); }

            // Warm the neighbours so the arrows feel instant.
            [index + 1, index - 1].forEach(function (j) {
                var q = pictures[(j + n) % n];
                if (q !== p) { (new Image()).src = q.src; }
            });
        }

        function open() {
            if (!viewer) {
                viewer = new Viewer(pictures, {
                    strings: t,
                    distributions: opts.distributions,
                    onChange: function (i) { if (i !== index) { show(i, true); } },
                });
            }
            viewer.open(index, stage);
        }

        stage.addEventListener('click', open);
        stage.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowLeft' && n > 1) { e.preventDefault(); show(index - 1); }
            else if (e.key === 'ArrowRight' && n > 1) { e.preventDefault(); show(index + 1); }
            else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
        });
        var openBtn = card.querySelector('[data-ep-open]');
        if (openBtn) { openBtn.addEventListener('click', open); }

        show(0, true);

        card.epInstance = {
            show: show,
            open: open,
            viewer: function () { return viewer; },
            destroy: function () {
                seq++;
                if (viewer) { viewer.destroy(); }
                viewer = null;
            },
        };
        return card.epInstance;
    }

    window.EventPictures = { mount: mount };
}());
