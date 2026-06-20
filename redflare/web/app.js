"use strict";

const NS = "http://www.w3.org/2000/svg";
const TYPE_STYLE = {
  run:       { color: "#ff4d5f", size: 26, icon: "RF", order: 0 },
  target:    { color: "#4ad9d9", size: 22, icon: "◎", order: 1 },
  endpoint:  { color: "#58a6ff", size: 13, icon: "↗", order: 2 },
  module:    { color: "#f59e42", size: 12, icon: "m", order: 2 },
  parameter: { color: "#ac7cff", size: 8,  icon: "p", order: 3 },
  document:  { color: "#4fd18b", size: 12, icon: "≡", order: 3 },
  finding:   { color: "#e8c547", size: 12, icon: "!", order: 4 },
  exposure:  { color: "#ff4055", size: 15, icon: "!", order: 4 },
  standard:  { color: "#8491a3", size: 9,  icon: "§", order: 5 },
};
const SEVERITY_COLOR = { critical: "#ff4055", high: "#ff874d", medium: "#e8c547", low: "#58a6ff", info: "#8491a3" };

const state = {
  graph: null,
  nodes: [],
  edges: [],
  nodeMap: new Map(),
  hiddenTypes: new Set(),
  layout: "force",
  selected: null,
  connected: new Set(),
  search: "",
  matches: new Set(),
  transform: { x: 0, y: 0, k: 1 },
  animation: null,
  dragged: null,
  dragStart: null,
  dragMoved: false,
  suppressClick: false,
  panning: null,
};

const svg = document.getElementById("graph");
const viewport = document.getElementById("viewport");
const edgeLayer = document.getElementById("edges");
const edgeLabelLayer = document.getElementById("edge-labels");
const nodeLayer = document.getElementById("nodes");
const tooltip = document.getElementById("tooltip");

function el(tag, attrs = {}, text = null) {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  if (text !== null) node.textContent = text;
  return node;
}

function htmlEl(tag, className = "", text = null) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== null) node.textContent = text;
  return node;
}

async function boot() {
  const response = await fetch("/api/graph", { cache: "no-store" });
  if (!response.ok) throw new Error(`Graph request failed: ${response.status}`);
  state.graph = await response.json();
  state.nodes = state.graph.nodes.map((node, index) => ({ ...node, x: 0, y: 0, vx: 0, vy: 0, index }));
  state.edges = state.graph.edges.map(edge => ({ ...edge }));
  state.nodeMap = new Map(state.nodes.map(node => [node.id, node]));
  document.getElementById("run-id").textContent = state.graph.metadata.run_id;
  buildStats();
  buildFilters();
  bindControls();
  seedPositions();
  applyLayout("force");
  requestAnimationFrame(() => fitView(false));
}

function buildStats() {
  const meta = state.graph.metadata;
  const stats = document.getElementById("stats");
  stats.replaceChildren();
  const values = [
    [meta.nodes, "nodes"], [meta.edges, "edges"],
    [meta.type_counts.endpoint || 0, "endpoints"],
    [(meta.type_counts.finding || 0) + (meta.type_counts.exposure || 0), "findings"],
  ];
  for (const [value, label] of values) {
    const card = htmlEl("div", "stat");
    card.append(htmlEl("strong", "", String(value)), htmlEl("span", "", label));
    stats.append(card);
  }
}

function buildFilters() {
  const filters = document.getElementById("filters");
  filters.replaceChildren();
  const counts = state.graph.metadata.type_counts;
  const types = Object.keys(counts).sort((a, b) => (TYPE_STYLE[a]?.order ?? 99) - (TYPE_STYLE[b]?.order ?? 99));
  for (const type of types) {
    const row = htmlEl("label", "filter-row");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = true;
    input.dataset.type = type;
    input.addEventListener("change", () => {
      input.checked ? state.hiddenTypes.delete(type) : state.hiddenTypes.add(type);
      applyLayout(state.layout, true);
    });
    const swatch = htmlEl("span", "swatch");
    swatch.style.color = TYPE_STYLE[type]?.color || "#8491a3";
    swatch.style.background = TYPE_STYLE[type]?.color || "#8491a3";
    row.append(input, swatch, htmlEl("span", "", labelFor(type)), htmlEl("span", "filter-count", String(counts[type])));
    filters.append(row);
  }
}

function bindControls() {
  document.querySelectorAll(".layout-button").forEach(button => button.addEventListener("click", () => applyLayout(button.dataset.layout)));
  document.getElementById("fit-view").addEventListener("click", () => fitView(true));
  document.getElementById("reset-focus").addEventListener("click", clearFocus);
  document.getElementById("show-all").addEventListener("click", () => {
    state.hiddenTypes.clear();
    document.querySelectorAll("#filters input").forEach(input => { input.checked = true; });
    applyLayout(state.layout, true);
  });
  const search = document.getElementById("graph-search");
  search.addEventListener("input", () => { state.search = search.value.trim().toLowerCase(); updateSearch(); renderClasses(); });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape") clearFocus();
    if (event.key === "/" && document.activeElement !== search) { event.preventDefault(); search.focus(); }
    if (event.key.toLowerCase() === "f" && document.activeElement !== search) fitView(true);
  });

  svg.addEventListener("wheel", event => {
    event.preventDefault();
    const point = svgPoint(event.clientX, event.clientY);
    const old = state.transform.k;
    const next = clamp(old * (event.deltaY < 0 ? 1.12 : .89), .12, 5);
    state.transform.x = event.clientX - svg.getBoundingClientRect().left - (point.x * next);
    state.transform.y = event.clientY - svg.getBoundingClientRect().top - (point.y * next);
    state.transform.k = next;
    applyTransform();
  }, { passive: false });

  svg.addEventListener("pointerdown", event => {
    if (event.target.closest?.(".node")) return;
    state.panning = { x: event.clientX, y: event.clientY, tx: state.transform.x, ty: state.transform.y };
    svg.classList.add("panning");
    svg.setPointerCapture(event.pointerId);
  });
  svg.addEventListener("pointermove", event => {
    if (state.dragged) {
      if (state.dragStart && Math.hypot(event.clientX - state.dragStart.x, event.clientY - state.dragStart.y) > 4) state.dragMoved = true;
      const point = svgPoint(event.clientX, event.clientY);
      state.dragged.x = point.x;
      state.dragged.y = point.y;
      state.dragged.fx = point.x;
      state.dragged.fy = point.y;
      updateGeometry();
    } else if (state.panning) {
      state.transform.x = state.panning.tx + event.clientX - state.panning.x;
      state.transform.y = state.panning.ty + event.clientY - state.panning.y;
      applyTransform();
    }
  });
  svg.addEventListener("pointerup", event => {
    if (state.dragged) { state.dragged.fx = null; state.dragged.fy = null; }
    state.suppressClick = state.dragMoved;
    state.dragged = null;
    state.dragStart = null;
    state.dragMoved = false;
    state.panning = null;
    svg.classList.remove("panning");
    try { if (svg.hasPointerCapture(event.pointerId)) svg.releasePointerCapture(event.pointerId); } catch (_) {}
  });
  svg.addEventListener("click", event => { if (event.target === svg) clearFocus(); });
  new ResizeObserver(() => { if (state.layout !== "force") applyLayout(state.layout, true); }).observe(svg);
}

function visibleGraph() {
  const nodes = state.nodes.filter(node => !state.hiddenTypes.has(node.type));
  const ids = new Set(nodes.map(node => node.id));
  const edges = state.edges.filter(edge => ids.has(edge.source) && ids.has(edge.target));
  return { nodes, edges, ids };
}

function applyLayout(layout, preserveTransform = false) {
  state.layout = layout;
  document.querySelectorAll(".layout-button").forEach(button => button.classList.toggle("active", button.dataset.layout === layout));
  if (state.animation) cancelAnimationFrame(state.animation);
  const graph = visibleGraph();
  document.getElementById("visible-count").textContent = `${graph.nodes.length} nodes · ${graph.edges.length} edges`;
  document.getElementById("empty-state").classList.toggle("hidden", graph.nodes.length > 0);
  document.getElementById("graph-stage").classList.toggle("dense", graph.nodes.length > 75);
  if (layout === "tree") layoutTree(graph.nodes, graph.edges);
  else if (layout === "radial") layoutRadial(graph.nodes, graph.edges);
  else startForce(graph.nodes, graph.edges);
  renderGraph(graph.nodes, graph.edges);
  updateSearch();
  renderClasses();
  if (!preserveTransform && layout !== "force") requestAnimationFrame(() => fitView(true));
}

function seedPositions() {
  const { width, height } = dimensions();
  state.nodes.forEach((node, index) => {
    const angle = (index / Math.max(1, state.nodes.length)) * Math.PI * 2;
    const ring = 70 + (TYPE_STYLE[node.type]?.order || 1) * 65;
    node.x = width / 2 + Math.cos(angle) * ring + (Math.random() - .5) * 50;
    node.y = height / 2 + Math.sin(angle) * ring + (Math.random() - .5) * 50;
  });
}

function startForce(nodes, edges) {
  const { width, height } = dimensions();
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  let alpha = 1;
  const step = () => {
    alpha *= .965;
    const n = nodes.length;
    if (n <= 480) {
      for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) repel(nodes[i], nodes[j], alpha);
    } else {
      for (let i = 0; i < n; i++) for (let offset = 1; offset <= 36; offset++) repel(nodes[i], nodes[(i + offset * 17) % n], alpha * .7);
    }
    for (const edge of edges) {
      const source = nodeMap.get(edge.source), target = nodeMap.get(edge.target);
      if (!source || !target) continue;
      const dx = target.x - source.x, dy = target.y - source.y;
      const distance = Math.sqrt(dx * dx + dy * dy) || 1;
      const desired = edge.type === "maps_to" ? 115 : edge.type === "accepts" ? 75 : 145;
      const force = (distance - desired) * .012 * alpha;
      source.vx += dx / distance * force; source.vy += dy / distance * force;
      target.vx -= dx / distance * force; target.vy -= dy / distance * force;
    }
    for (const node of nodes) {
      if (node.fx != null) { node.x = node.fx; node.y = node.fy; node.vx = node.vy = 0; continue; }
      node.vx += (width / 2 - node.x) * .0009 * alpha;
      node.vy += (height / 2 - node.y) * .0009 * alpha;
      node.vx *= .84; node.vy *= .84;
      node.x += node.vx; node.y += node.vy;
    }
    updateGeometry();
    if (alpha > .025 && state.layout === "force") state.animation = requestAnimationFrame(step);
  };
  state.animation = requestAnimationFrame(step);
}

function repel(a, b, alpha) {
  if (a === b) return;
  let dx = b.x - a.x, dy = b.y - a.y;
  let d2 = dx * dx + dy * dy;
  if (d2 < 1) { dx = Math.random() - .5; dy = Math.random() - .5; d2 = 1; }
  const min = radius(a) + radius(b) + 16;
  const strength = (d2 < min * min ? 6800 : 2300) * alpha / d2;
  a.vx -= dx * strength; a.vy -= dy * strength;
  b.vx += dx * strength; b.vy += dy * strength;
}

function levelsFor(nodes, edges) {
  const ids = new Set(nodes.map(node => node.id));
  const incoming = new Map(nodes.map(node => [node.id, 0]));
  const children = new Map(nodes.map(node => [node.id, []]));
  for (const edge of edges) if (ids.has(edge.source) && ids.has(edge.target)) {
    children.get(edge.source).push(edge.target);
    incoming.set(edge.target, (incoming.get(edge.target) || 0) + 1);
  }
  const roots = nodes.filter(node => node.type === "run" || incoming.get(node.id) === 0);
  const levels = new Map();
  const queue = roots.map(node => [node.id, 0]);
  while (queue.length) {
    const [id, level] = queue.shift();
    if (levels.has(id) && levels.get(id) <= level) continue;
    levels.set(id, level);
    for (const child of children.get(id) || []) queue.push([child, level + 1]);
  }
  for (const node of nodes) if (!levels.has(node.id)) levels.set(node.id, TYPE_STYLE[node.type]?.order || 5);
  return levels;
}

function layoutTree(nodes, edges) {
  const { width } = dimensions();
  const levels = levelsFor(nodes, edges);
  const groups = new Map();
  nodes.forEach(node => { const level = levels.get(node.id); if (!groups.has(level)) groups.set(level, []); groups.get(level).push(node); });
  const maxLevel = Math.max(0, ...groups.keys());
  for (const [level, group] of groups) {
    group.sort((a, b) => a.type.localeCompare(b.type) || a.label.localeCompare(b.label));
    group.forEach((node, index) => {
      node.x = ((index + 1) / (group.length + 1)) * Math.max(width, group.length * 115);
      node.y = 90 + level * 145;
    });
  }
  viewport.dataset.height = String(180 + maxLevel * 145);
}

function layoutRadial(nodes, edges) {
  const { width, height } = dimensions();
  const levels = levelsFor(nodes, edges);
  const groups = new Map();
  nodes.forEach(node => { const level = levels.get(node.id); if (!groups.has(level)) groups.set(level, []); groups.get(level).push(node); });
  const cx = width / 2, cy = height / 2;
  for (const [level, group] of groups) {
    const ring = level * 125;
    group.sort((a, b) => a.type.localeCompare(b.type) || a.label.localeCompare(b.label));
    group.forEach((node, index) => {
      const angle = (index / Math.max(1, group.length)) * Math.PI * 2 - Math.PI / 2;
      node.x = cx + Math.cos(angle) * ring;
      node.y = cy + Math.sin(angle) * ring;
    });
  }
}

function renderGraph(nodes, edges) {
  edgeLayer.replaceChildren(); edgeLabelLayer.replaceChildren(); nodeLayer.replaceChildren();
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  for (const edge of edges) {
    const source = nodeMap.get(edge.source), target = nodeMap.get(edge.target);
    if (!source || !target) continue;
    const line = el("line", { class: "edge", "data-id": edge.id });
    line.__data__ = edge;
    edgeLayer.append(line);
    if (edge.type !== "contains" && edge.type !== "serves") {
      const label = el("text", { class: "edge-label", "data-id": edge.id }, edge.label || edge.type);
      label.__data__ = edge;
      edgeLabelLayer.append(label);
    }
  }
  for (const node of nodes) {
    const style = TYPE_STYLE[node.type] || { color: "#8491a3", size: 10, icon: "?" };
    const color = node.severity ? SEVERITY_COLOR[node.severity] || style.color : style.color;
    const group = el("g", { class: "node", "data-id": node.id, "data-type": node.type, tabindex: "0", role: "button", "aria-label": `${node.type}: ${node.label}` });
    group.__data__ = node;
    group.append(el("circle", { class: "node-ring", r: style.size + 5 }));
    group.append(el("circle", { class: "node-circle", r: style.size, fill: color }));
    group.append(el("text", { class: "node-icon", y: 1 }, style.icon));
    group.append(el("text", { class: "node-label", y: style.size + 15 }, truncate(node.label, node.type === "endpoint" ? 32 : 24)));
    if (node.type === "exposure") {
      group.append(el("circle", { class: "node-badge", cx: style.size - 1, cy: -style.size + 1, r: 6 }));
      group.append(el("text", { class: "node-badge-text", x: style.size - 1, y: -style.size + 1 }, "!"));
    }
    group.addEventListener("pointerdown", event => {
      event.stopPropagation();
      state.dragged = node;
      state.dragStart = { x: event.clientX, y: event.clientY };
      state.dragMoved = false;
      group.setPointerCapture(event.pointerId);
    });
    group.addEventListener("click", event => {
      event.stopPropagation();
      if (state.suppressClick) { state.suppressClick = false; return; }
      selectNode(node.id);
    });
    group.addEventListener("dblclick", event => { event.stopPropagation(); selectNode(node.id); centerOnNode(node); });
    group.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") selectNode(node.id); });
    group.addEventListener("mouseenter", event => showTooltip(event, node));
    group.addEventListener("mousemove", moveTooltip);
    group.addEventListener("mouseleave", hideTooltip);
    nodeLayer.append(group);
  }
  updateGeometry();
}

function updateGeometry() {
  edgeLayer.querySelectorAll(".edge").forEach(line => {
    const edge = line.__data__, source = state.nodeMap.get(edge.source), target = state.nodeMap.get(edge.target);
    if (!source || !target) return;
    line.setAttribute("x1", source.x); line.setAttribute("y1", source.y); line.setAttribute("x2", target.x); line.setAttribute("y2", target.y);
  });
  edgeLabelLayer.querySelectorAll(".edge-label").forEach(label => {
    const edge = label.__data__, source = state.nodeMap.get(edge.source), target = state.nodeMap.get(edge.target);
    if (!source || !target) return;
    label.setAttribute("x", (source.x + target.x) / 2); label.setAttribute("y", (source.y + target.y) / 2);
  });
  nodeLayer.querySelectorAll(".node").forEach(group => {
    const node = group.__data__; group.setAttribute("transform", `translate(${node.x},${node.y})`);
  });
}

function selectNode(id) {
  state.selected = id;
  state.connected = new Set([id]);
  for (const edge of state.edges) {
    if (edge.source === id) state.connected.add(edge.target);
    if (edge.target === id) state.connected.add(edge.source);
  }
  renderClasses();
  renderDetails(state.nodeMap.get(id));
}

function clearFocus() {
  state.selected = null; state.connected.clear();
  document.getElementById("detail").classList.add("hidden");
  document.getElementById("detail-empty").classList.remove("hidden");
  renderClasses();
}

function renderClasses() {
  nodeLayer.querySelectorAll(".node").forEach(group => {
    const id = group.dataset.id;
    group.classList.toggle("focused", id === state.selected);
    group.classList.toggle("dimmed", state.selected !== null && !state.connected.has(id));
    group.classList.toggle("match", state.matches.has(id));
  });
  edgeLayer.querySelectorAll(".edge").forEach(line => {
    const edge = line.__data__;
    const connected = state.selected && (edge.source === state.selected || edge.target === state.selected);
    line.classList.toggle("focused", Boolean(connected));
    line.classList.toggle("dimmed", state.selected !== null && !connected);
  });
  edgeLabelLayer.querySelectorAll(".edge-label").forEach(label => {
    const edge = label.__data__;
    label.classList.toggle("focused", Boolean(state.selected && (edge.source === state.selected || edge.target === state.selected)));
  });
}

function updateSearch() {
  state.matches.clear();
  if (state.search) for (const node of state.nodes) {
    const haystack = `${node.label} ${node.type} ${node.severity || ""} ${JSON.stringify(node.info || {})}`.toLowerCase();
    if (haystack.includes(state.search)) state.matches.add(node.id);
  }
  document.getElementById("search-count").textContent = state.search ? String(state.matches.size) : "";
}

function renderDetails(node) {
  if (!node) return;
  document.getElementById("detail-empty").classList.add("hidden");
  document.getElementById("detail").classList.remove("hidden");
  const style = TYPE_STYLE[node.type] || { icon: "?" };
  document.getElementById("detail-icon").textContent = style.icon;
  document.getElementById("detail-title").textContent = node.label;
  const type = document.getElementById("detail-type");
  type.textContent = node.severity ? `${node.type} · ${node.severity}` : node.type;
  type.className = `pill ${node.severity || ""}`;

  const links = document.getElementById("detail-links"); links.replaceChildren();
  for (const candidate of findUrls(node.info)) {
    const anchor = htmlEl("a", "pill", "open reference");
    anchor.href = candidate; anchor.target = "_blank"; anchor.rel = "noopener noreferrer";
    links.append(anchor);
  }
  const props = document.getElementById("detail-properties"); props.replaceChildren();
  appendProperties(props, node.info || {});
  const relations = document.getElementById("detail-relations"); relations.replaceChildren();
  for (const edge of state.edges.filter(edge => edge.source === node.id || edge.target === node.id)) {
    const otherId = edge.source === node.id ? edge.target : edge.source;
    const other = state.nodeMap.get(otherId); if (!other) continue;
    const row = htmlEl("div", "relation");
    row.append(htmlEl("span", "relation-type", edge.type), htmlEl("span", "", other.label));
    row.addEventListener("click", () => selectNode(otherId));
    relations.append(row);
  }
}

function appendProperties(parent, value, prefix = "") {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => appendProperties(parent, item, `${prefix}[${index + 1}]`));
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value)) appendProperties(parent, item, prefix ? `${prefix}.${key}` : key);
    return;
  }
  const row = htmlEl("div", "property");
  row.append(htmlEl("div", "property-key", prefix), htmlEl("div", "property-value", String(value)));
  parent.append(row);
}

function findUrls(value, found = new Set()) {
  if (typeof value === "string" && /^https?:\/\//i.test(value)) found.add(value);
  else if (Array.isArray(value)) value.forEach(item => findUrls(item, found));
  else if (value && typeof value === "object") Object.values(value).forEach(item => findUrls(item, found));
  return [...found].slice(0, 6);
}

function showTooltip(event, node) {
  tooltip.textContent = `${node.label}\n${labelFor(node.type)}${node.severity ? ` · ${node.severity}` : ""}\nClick to inspect relationships`;
  tooltip.classList.add("visible"); moveTooltip(event);
}
function moveTooltip(event) { tooltip.style.left = `${event.clientX + 14}px`; tooltip.style.top = `${event.clientY + 12}px`; }
function hideTooltip() { tooltip.classList.remove("visible"); }

function fitView(animate = true) {
  const graph = visibleGraph(); if (!graph.nodes.length) return;
  const xs = graph.nodes.map(node => node.x), ys = graph.nodes.map(node => node.y);
  const minX = Math.min(...xs) - 55, maxX = Math.max(...xs) + 55, minY = Math.min(...ys) - 55, maxY = Math.max(...ys) + 55;
  const { width, height } = dimensions();
  const k = clamp(Math.min(width / Math.max(1, maxX - minX), height / Math.max(1, maxY - minY)) * .9, .12, 2.2);
  const next = { x: width / 2 - ((minX + maxX) / 2) * k, y: height / 2 - ((minY + maxY) / 2) * k, k };
  if (!animate) { state.transform = next; applyTransform(); return; }
  const start = { ...state.transform }, started = performance.now();
  const frame = now => {
    const t = Math.min(1, (now - started) / 280), eased = 1 - Math.pow(1 - t, 3);
    state.transform = { x: lerp(start.x, next.x, eased), y: lerp(start.y, next.y, eased), k: lerp(start.k, next.k, eased) };
    applyTransform(); if (t < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

function centerOnNode(node) {
  const { width, height } = dimensions();
  const next = { x: width / 2 - node.x * Math.max(1.35, state.transform.k), y: height / 2 - node.y * Math.max(1.35, state.transform.k), k: Math.max(1.35, state.transform.k) };
  const start = { ...state.transform }, started = performance.now();
  const frame = now => {
    const t = Math.min(1, (now - started) / 240), eased = 1 - Math.pow(1 - t, 3);
    state.transform = { x: lerp(start.x, next.x, eased), y: lerp(start.y, next.y, eased), k: lerp(start.k, next.k, eased) };
    applyTransform(); if (t < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

function applyTransform() { viewport.setAttribute("transform", `translate(${state.transform.x},${state.transform.y}) scale(${state.transform.k})`); }
function svgPoint(clientX, clientY) { const rect = svg.getBoundingClientRect(); return { x: (clientX - rect.left - state.transform.x) / state.transform.k, y: (clientY - rect.top - state.transform.y) / state.transform.k }; }
function dimensions() { const rect = svg.getBoundingClientRect(); return { width: Math.max(400, rect.width), height: Math.max(320, rect.height) }; }
function radius(node) { return TYPE_STYLE[node.type]?.size || 10; }
function truncate(value, length) { value = String(value || ""); return value.length > length ? value.slice(0, length - 1) + "…" : value; }
function labelFor(value) { return String(value).replaceAll("_", " ").replace(/\b\w/g, letter => letter.toUpperCase()); }
function clamp(value, min, max) { return Math.max(min, Math.min(max, value)); }
function lerp(a, b, t) { return a + (b - a) * t; }

boot().catch(error => {
  document.getElementById("run-id").textContent = "Unable to load run";
  document.getElementById("graph-status").textContent = "error";
  document.getElementById("empty-state").textContent = error.message;
  document.getElementById("empty-state").classList.remove("hidden");
});
