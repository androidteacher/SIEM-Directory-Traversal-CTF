/* Polaris Cloud — Nightwatch console. Framework-free progressive enhancement. */
(function () {
  "use strict";

  /* ---------- chart tooltips ---------- */
  var tip = document.createElement("div");
  tip.className = "tooltip";
  document.body.appendChild(tip);
  function showTip(txt, x, y) {
    tip.textContent = txt;
    tip.classList.add("on");
    var pad = 14;
    tip.style.left = Math.min(x + pad, window.innerWidth - tip.offsetWidth - 8) + "px";
    tip.style.top = (y - tip.offsetHeight - 10) + "px";
  }
  function hideTip() { tip.classList.remove("on"); }
  document.addEventListener("mouseover", function (e) {
    var t = e.target.closest && e.target.closest("[data-tip]");
    if (t) showTip(t.getAttribute("data-tip"), e.clientX, e.clientY);
  });
  document.addEventListener("mousemove", function (e) {
    if (tip.classList.contains("on")) {
      var t = e.target.closest && e.target.closest("[data-tip]");
      if (t) showTip(t.getAttribute("data-tip"), e.clientX, e.clientY); else hideTip();
    }
  });

  /* ---------- sortable tables ---------- */
  function cellVal(row, i) {
    var td = row.children[i];
    if (!td) return { num: null, str: "" };
    var ds = td.getAttribute("data-sort");          // explicit sort key (e.g. raw bytes)
    if (ds !== null) {
      var dn = parseFloat(ds);
      return { num: isNaN(dn) ? null : dn, str: ds.toLowerCase() };
    }
    var s = td.textContent.trim();
    var n = parseFloat(s.replace(/[^0-9.\-]/g, ""));
    return { num: isNaN(n) ? null : n, str: s.toLowerCase() };
  }
  document.querySelectorAll("table[data-sortable]").forEach(function (table) {
    var ths = table.tHead ? table.tHead.rows[0].cells : [];
    Array.prototype.forEach.call(ths, function (th, idx) {
      if (!th.classList.contains("sortable")) return;
      th.setAttribute("tabindex", "0");
      th.setAttribute("role", "button");
      function sort() {
        var dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
        Array.prototype.forEach.call(ths, function (o) { o.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", dir);
        var body = table.tBodies[0];
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (a, b) {
          var av = cellVal(a, idx), bv = cellVal(b, idx), r;
          if (av.num !== null && bv.num !== null) r = av.num - bv.num;
          else r = av.str < bv.str ? -1 : av.str > bv.str ? 1 : 0;
          return dir === "ascending" ? r : -r;
        });
        rows.forEach(function (r) { body.appendChild(r); });
      }
      th.addEventListener("click", sort);
      th.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); }
      });
    });
  });

  /* ---------- severity filter chips ---------- */
  document.querySelectorAll("[data-filter-group]").forEach(function (group) {
    var table = document.querySelector("table[data-filterable]");
    group.querySelectorAll(".chip").forEach(function (chip) {
      chip.setAttribute("tabindex", "0");
      function apply() {
        group.querySelectorAll(".chip").forEach(function (c) { c.setAttribute("aria-pressed", "false"); });
        chip.setAttribute("aria-pressed", "true");
        var f = chip.getAttribute("data-filter");
        if (!table) return;
        Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
          var sev = row.getAttribute("data-sev");
          row.style.display = (f === "all" || sev === f) ? "" : "none";
        });
      }
      chip.addEventListener("click", apply);
      chip.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); apply(); }
      });
    });
  });

  /* ---------- single-select cosmetic chip groups (e.g. time range) ---------- */
  document.querySelectorAll(".chips:not([data-filter-group])").forEach(function (group) {
    group.querySelectorAll(".chip[aria-pressed]").forEach(function (chip) {
      chip.setAttribute("tabindex", "0");
      function pick() {
        group.querySelectorAll(".chip[aria-pressed]").forEach(function (c) { c.setAttribute("aria-pressed", "false"); });
        chip.setAttribute("aria-pressed", "true");
      }
      chip.addEventListener("click", pick);
      chip.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); }
      });
    });
  });
})();

/* ---------- dynamic "Global threat activity" map ---------- */
(function initThreatMap() {
  "use strict";
  var svg = document.getElementById("threatmap");
  if (!svg) return;
  var NS = "http://www.w3.org/2000/svg";
  var layer = svg.querySelector(".arc-layer");
  var HX = parseFloat(svg.dataset.hx), HY = parseFloat(svg.dataset.hy);
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // origin points scattered across the map (viewBox 1000x460)
  // origins kept well clear of the home node so IP labels never crowd "us-tex-1"
  var ORIGINS = [
    [812,150],[523,128],[868,236],[470,300],[360,360],[640,110],[760,180],
    [905,140],[560,300],[690,330],[430,330],[840,320],[600,180],[700,90]
  ];
  var SEV = ["#FF5468","#FF8A4C","#F5A524","#2DD4BF"];
  var BUSY = {};                                    // origin indices currently animating
  function freeOrigin(){
    var avail = [];
    for (var j = 0; j < ORIGINS.length; j++) if (!BUSY[j]) avail.push(j);
    return avail.length ? avail[Math.floor(Math.random()*avail.length)] : -1;
  }

  function ri(n){ return Math.floor(Math.random() * n); }
  // pool of fictional IPs (RFC5737 TEST-NET + RFC1918 internal)
  function genIP(){
    var docnets = ["203.0.113","198.51.100","192.0.2"];
    if (ri(6) === 0) return "10." + ri(256) + "." + ri(256) + "." + (1 + ri(254));
    return docnets[ri(docnets.length)] + "." + (1 + ri(254));
  }
  var IP_POOL = [];
  for (var i = 0; i < 24; i++) IP_POOL.push(genIP());

  function el(name, attrs){
    var e = document.createElementNS(NS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function arcD(x1,y1,x2,y2){
    var mx = (x1+x2)/2, my = (y1+y2)/2;
    var cy = my - Math.hypot(x2-x1, y2-y1) * 0.30;
    return "M"+x1+","+y1+" Q"+mx.toFixed(1)+","+cy.toFixed(1)+" "+x2+","+y2;
  }

  function spawn(){
    if (layer.childElementCount > 6) return;        // concurrency cap
    var idx = freeOrigin();
    if (idx < 0) return;                            // all origins busy
    BUSY[idx] = true;
    var o = ORIGINS[idx];
    var color = SEV[ri(SEV.length)];
    var ip = IP_POOL[ri(IP_POOL.length)];
    var g = el("g", {});
    var path = el("path", {d: arcD(o[0],o[1],HX,HY), fill:"none", stroke:color,
      "stroke-width":"1.6", "stroke-linecap":"round", opacity:"0.9"});
    g.appendChild(path);
    g.appendChild(el("circle", {cx:o[0], cy:o[1], r:"2.6", fill:color}));
    var ping = el("circle", {cx:o[0], cy:o[1], r:"3", fill:"none", stroke:color, "stroke-width":"1.3", opacity:"0.9"});
    g.appendChild(ping);
    var label = el("text", {x:o[0]+8, y:o[1]-8, fill:"#8696AC", "font-size":"10",
      "font-family":"IBM Plex Mono,monospace", opacity:"0"});
    label.textContent = ip;
    g.appendChild(label);
    var dot = el("circle", {cx:o[0], cy:o[1], r:"3.2", fill:color});
    g.appendChild(dot);
    layer.appendChild(g);

    var len = path.getTotalLength();
    var dur = 1200 + ri(1100);
    path.style.strokeDasharray = len;
    path.style.strokeDashoffset = len;
    void path.getBoundingClientRect();              // reflow
    path.style.transition = "stroke-dashoffset " + dur + "ms linear";
    path.style.strokeDashoffset = "0";
    label.style.transition = "opacity 300ms"; label.setAttribute("opacity", "1");
    ping.style.transition = "r 700ms ease-out, opacity 700ms ease-out";
    requestAnimationFrame(function(){ ping.setAttribute("r","15"); ping.setAttribute("opacity","0"); });

    var start = performance.now();
    (function frame(t){
      var p = Math.min((t - start) / dur, 1);
      var pt = path.getPointAtLength(p * len);
      dot.setAttribute("cx", pt.x); dot.setAttribute("cy", pt.y);
      if (p < 1) requestAnimationFrame(frame);
      else {
        dot.setAttribute("opacity", "0");
        g.style.transition = "opacity 900ms";
        setTimeout(function(){ g.style.opacity = "0"; }, 500);
        setTimeout(function(){ if (g.parentNode) g.parentNode.removeChild(g); delete BUSY[idx]; }, 1500);
      }
    })(start);
  }

  if (reduce){                                      // static snapshot, no motion
    for (var s = 0; s < 5; s++){
      var o = ORIGINS[(s*3) % ORIGINS.length], color = SEV[s % SEV.length];
      layer.appendChild(el("path", {d:arcD(o[0],o[1],HX,HY), fill:"none", stroke:color,
        "stroke-width":"1.4", "stroke-dasharray":"5 7", opacity:"0.7"}));
      layer.appendChild(el("circle", {cx:o[0], cy:o[1], r:"2.6", fill:color}));
    }
    return;
  }

  (function loop(){
    if (!document.hidden) spawn();
    setTimeout(loop, 500 + ri(1100));               // irregular cadence
  })();
  setTimeout(spawn, 350);                           // avoid an empty map on load
})();

/* ---------- log / flow search filter ---------- */
(function () {
  "use strict";
  document.querySelectorAll("[data-logsearch]").forEach(function (input) {
    var sel = input.getAttribute("data-logsearch");
    var table = document.querySelector(sel);
    if (!table || !table.tBodies.length) return;
    var countEl = document.querySelector('[data-count-for="' + sel + '"]');
    var rows = Array.prototype.slice.call(table.tBodies[0].rows);
    function update() {
      var q = input.value.trim().toLowerCase(), shown = 0;
      rows.forEach(function (r) {
        var ok = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
        r.style.display = ok ? "" : "none";
        if (ok) shown++;
      });
      if (countEl) countEl.textContent = shown + " of " + rows.length;
    }
    input.addEventListener("input", update);
    update();
  });
})();

/* ---------- clickable table rows ---------- */
(function () {
  "use strict";
  document.querySelectorAll("tr[data-href]").forEach(function (row) {
    row.style.cursor = "pointer";
    row.addEventListener("click", function (e) {
      if (e.target.closest("a,button")) return;     // let real links/buttons win
      window.location.href = row.getAttribute("data-href");
    });
  });
})();

/* ---------- "Stop this server" -> offboarding notice (lab easter egg) ---------- */
(function () {
  "use strict";
  var stops = document.querySelectorAll("[data-stop]");
  if (!stops.length) return;
  var NS_ALERT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" '
    + 'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    + '<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/></svg>';
  var lastFocus = null;

  function closeModal(bd) {
    bd.classList.remove("on");
    setTimeout(function () { if (bd.parentNode) bd.parentNode.removeChild(bd); }, 200);
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function openModal(server) {
    lastFocus = document.activeElement;
    var bd = document.createElement("div");
    bd.className = "modal-backdrop";
    var modal = document.createElement("div");
    modal.className = "modal";
    modal.setAttribute("role", "alertdialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-labelledby", "offb-t");
    modal.innerHTML =
      '<div class="mark">' + NS_ALERT + '</div>'
      + '<h2 id="offb-t">Offboarding initiated</h2>'
      + '<p class="srv">server: ' + server + '</p>'
      + '<p>You were warned not to stop this server! Please report to Human Resources '
      + 'for offboarding.<span class="fired">You are fired!!!!!</span></p>'
      + '<button type="button" class="btn ghost" data-dismiss>Report to HR</button>';
    bd.appendChild(modal);
    document.body.appendChild(bd);
    requestAnimationFrame(function () { bd.classList.add("on"); });

    var dismiss = modal.querySelector("[data-dismiss]");
    dismiss.focus();
    dismiss.addEventListener("click", function () { closeModal(bd); });
    bd.addEventListener("click", function (e) { if (e.target === bd) closeModal(bd); });
    bd.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeModal(bd);
      if (e.key === "Tab") { e.preventDefault(); dismiss.focus(); }  // trap focus
    });
  }

  stops.forEach(function (btn) {
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();                          // never trigger the row link
      openModal(btn.getAttribute("data-stop") || "unknown");
    });
  });
})();

/* ---------- "Solution" nav link -> confirm before leaving the lab ---------- */
(function () {
  "use strict";
  var links = document.querySelectorAll("[data-confirm-solution]");
  if (!links.length) return;
  var NS_TARGET = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" '
    + 'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    + '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5"/></svg>';
  var lastFocus = null, box = null;

  function onKey(e) { if (e.key === "Escape") close(); }

  function close() {
    if (!box) return;
    var b = box; box = null;
    b.classList.remove("on");
    setTimeout(function () { if (b.parentNode) b.parentNode.removeChild(b); }, 200);
    document.removeEventListener("keydown", onKey);
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  function open(href) {
    lastFocus = document.activeElement;
    box = document.createElement("div");
    box.className = "modal-backdrop";
    var modal = document.createElement("div");
    modal.className = "modal ask";
    modal.setAttribute("role", "alertdialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-labelledby", "sol-t");
    modal.innerHTML =
      '<div class="mark">' + NS_TARGET + '</div>'
      + '<h2 id="sol-t">Read the solution?</h2>'
      + '<p>Are you sure you’re done poking around and want to read the '
      + 'solution / tutorial now?</p>'
      + '<div class="modal-actions">'
      + '<button type="button" class="btn ghost" data-no>No</button>'
      + '<button type="button" class="btn" data-yes>Yes, open it</button>'
      + '</div>';
    box.appendChild(modal);
    document.body.appendChild(box);
    requestAnimationFrame(function () { box.classList.add("on"); });

    var yes = modal.querySelector("[data-yes]");
    var no = modal.querySelector("[data-no]");
    no.focus();
    no.addEventListener("click", close);
    yes.addEventListener("click", function () { window.location.href = href; });
    box.addEventListener("click", function (e) { if (e.target === box) close(); });
    document.addEventListener("keydown", onKey);
  }

  links.forEach(function (a) {
    a.addEventListener("click", function (e) {
      e.preventDefault();
      open(a.getAttribute("href"));
    });
  });
})();
