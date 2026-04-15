import { N as C, S as _, E as b, T as k } from "./index--WAIHaIZ.js";
const I = 1e4, S = 2e4, M = 0.15 * S;
self.onmessage = (m) => {
  var D, h, t, c;
  if (m.data.source !== "simulation-worker-wrapper") return;
  const { nodes: p, edges: i, options: a, canvasBCR: d } = m.data, u = p.map((e) => {
    const y = new C(e.id, e.data, e.style);
    return y.setCircleRadius(e._circleRadius ?? 10), y;
  }), o = new Map(u.map((e) => [e.id, e]));
  (D = a.layout) == null || D.type;
  const { simulation: s, simulationForces: f } = _.initSimulationForces(a, d), g = [];
  for (const e of i) {
    const y = o.get(e.from.id), F = o.get(e.to.id);
    if (y && F) {
      const N = e.style ?? {};
      g.push(new b(e.id, y, F, e.data, N, e.directed));
    }
  }
  s.nodes(u);
  const T = s.force("link");
  T && T.id((e) => e.id).links(g), (((h = a.layout) == null ? void 0 : h.type) === "tree" || ((t = a.layout) == null ? void 0 : t.type) === "egoTree") && k.registerForcesOnSimulation(
    u,
    g,
    s,
    f,
    a.layout,
    d,
    k
  );
  let n = a.warmupTicks || S;
  n = n === "auto" ? S : n, n = n - M;
  let l = 0.3;
  s.alphaTarget(l);
  const r = (/* @__PURE__ */ new Date()).getTime();
  let w;
  for (let e = 0; e < n && !((/* @__PURE__ */ new Date()).getTime() - r > I || (/* @__PURE__ */ new Date()).getTime() - r > a.cooldownTime || E(a, s, l) && (/* @__PURE__ */ new Date()).getTime() - r > a.cooldownTime * 0.15); ++e)
    e % 5 === 0 && (w = A(e, (/* @__PURE__ */ new Date()).getTime() - r, a), postMessage({ type: "tick", progress: w, elapsedTime: (/* @__PURE__ */ new Date()).getTime() - r })), s.tick();
  l = 0, s.alphaTarget(l), s.alpha(1);
  for (let e = 0; e < M && !(E(a, s, l) && (/* @__PURE__ */ new Date()).getTime() - r > a.cooldownTime * 0.15); ++e)
    s.tick(), e % 5 === 0 && (w = A(n + e, (/* @__PURE__ */ new Date()).getTime() - r, a), postMessage({ type: "tick", progress: w, elapsedTime: (/* @__PURE__ */ new Date()).getTime() - r }));
  postMessage({ type: "tick", progress: 1, elapsedTime: (/* @__PURE__ */ new Date()).getTime() - r }), ((c = a.layout) == null ? void 0 : c.type) === "tree" && k.simulationDone(
    u,
    g,
    s,
    a.layout
  ), postMessage({
    type: "done",
    nodes: u.map((e) => e.toDict()),
    edges: g.map((e) => e.toDict())
  });
};
function O(m, p, i, a) {
  var r, w, D, h;
  const d = m.map((t) => {
    const c = new C(t.id, t.getData(), t.getStyle());
    return c.weight = t.weight || 1, c.setCircleRadius(t.getCircleRadius()), c;
  }), u = new Map(d.map((t) => [t.id, t]));
  (r = i.layout) == null || r.type;
  const { simulation: o, simulationForces: s } = _.initSimulationForces(i, a), f = [];
  for (const t of p) {
    const c = u.get(t.from.id), e = u.get(t.to.id);
    if (c && e) {
      const y = t.getStyle() ?? {};
      f.push(new b(t.id, c, e, t.getData(), y, t.directed));
    }
  }
  o.nodes(d);
  const g = o.force("link");
  g && g.id((t) => t.id).links(f), (((w = i.layout) == null ? void 0 : w.type) === "tree" || ((D = i.layout) == null ? void 0 : D.type) === "egoTree") && k.registerForcesOnSimulation(
    d,
    f,
    o,
    s,
    i.layout,
    a,
    k
  );
  let T;
  i.warmupTicks === "auto" || i.warmupTicks == null ? T = S : T = i.warmupTicks, T = T - M;
  let n = 0.3;
  o.alphaTarget(n);
  const l = (/* @__PURE__ */ new Date()).getTime();
  for (let t = 0; t < T && !((/* @__PURE__ */ new Date()).getTime() - l > I || (/* @__PURE__ */ new Date()).getTime() - l > i.cooldownTime || E(i, o, n) && (/* @__PURE__ */ new Date()).getTime() - l > i.cooldownTime * 0.15); ++t)
    o.tick();
  n = 0, o.alphaTarget(n), o.alpha(1);
  for (let t = 0; t < M && !(E(i, o, n) && (/* @__PURE__ */ new Date()).getTime() - l > i.cooldownTime * 0.15); ++t)
    o.tick();
  return ((h = i.layout) == null ? void 0 : h.type) === "tree" && k.simulationDone(
    d,
    f,
    o,
    i.layout
  ), {
    nodes: d,
    edges: f
  };
}
function A(m, p, i) {
  return p / i.cooldownTime;
}
function E(m, p, i) {
  return m.d3AlphaMin > 0 && p.alpha() - i < m.d3AlphaMin;
}
export {
  O as runSimulation
};
