// Atlantiraptor documentation: navigation, theme and search.
(function () {
  "use strict";
  var base = document.body.getAttribute("data-base") || "/";

  // Phone navigation drawer.
  var menu = document.querySelector(".menu-button");
  if (menu) {
    menu.addEventListener("click", function () {
      var open = document.body.classList.toggle("nav-open");
      menu.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("click", function (e) {
      if (document.body.classList.contains("nav-open") &&
          !e.target.closest(".sidebar") && !e.target.closest(".menu-button")) {
        document.body.classList.remove("nav-open");
        menu.setAttribute("aria-expanded", "false");
      }
    });
  }
  var current = document.querySelector(".sidebar a.current");
  if (current && current.scrollIntoView) {
    current.scrollIntoView({ block: "center" });
    window.scrollTo(0, 0);
  }

  // Light / dark theme toggle (remembered in this browser only).
  var themeButton = document.querySelector(".theme-button");
  if (themeButton) {
    themeButton.addEventListener("click", function () {
      var root = document.documentElement;
      var dark = root.getAttribute("data-theme") === "dark" ||
        (!root.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
      var next = dark ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("atl-docs-theme", next); } catch (e) {}
    });
  }

  // Highlight the section being read in the "On this page" list.
  var tocLinks = document.querySelectorAll(".toc a");
  if (tocLinks.length && "IntersectionObserver" in window) {
    var byId = {};
    tocLinks.forEach(function (a) { byId[decodeURIComponent(a.getAttribute("href").slice(1))] = a; });
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting && byId[en.target.id]) {
          tocLinks.forEach(function (a) { a.classList.remove("active"); });
          byId[en.target.id].classList.add("active");
        }
      });
    }, { rootMargin: "0px 0px -70% 0px" });
    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) obs.observe(el);
    });
  }

  // Search over search-index.json, loaded on first use.
  var input = document.getElementById("search-input");
  var box = document.getElementById("search-results");
  if (!input || !box) return;
  var index = null, loading = null, active = -1;

  function load() {
    if (index) return Promise.resolve(index);
    if (!loading) {
      loading = fetch(base + "search-index.json")
        .then(function (r) { return r.json(); })
        .then(function (d) {
          index = d.map(function (e) {
            return { t: e.t, u: e.u, s: e.s || "", x: e.x || "", tl: e.t.toLowerCase(), xl: (e.x || "").toLowerCase() };
          });
          return index;
        });
    }
    return loading;
  }

  function esc(s) {
    return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; });
  }

  function highlight(text, terms) {
    var out = esc(text);
    terms.forEach(function (t) {
      if (t.length < 2) return;
      var re = new RegExp("(" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
      out = out.replace(re, "<mark>$1</mark>");
    });
    return out;
  }

  function snippet(e, terms) {
    var pos = -1;
    for (var i = 0; i < terms.length && pos < 0; i++) pos = e.xl.indexOf(terms[i]);
    if (pos < 0) return e.x.slice(0, 140);
    var start = Math.max(0, pos - 50);
    return (start > 0 ? "…" : "") + e.x.slice(start, start + 160) + "…";
  }

  function search(q) {
    var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return [];
    var results = [];
    index.forEach(function (e) {
      var score = 0;
      for (var i = 0; i < terms.length; i++) {
        var t = terms[i];
        var inTitle = e.tl.indexOf(t) >= 0;
        var inText = e.xl.indexOf(t) >= 0;
        if (!inTitle && !inText) return;
        if (e.tl === t) score += 60;
        else if (e.tl.indexOf(t) === 0) score += 25;
        else if (inTitle) score += 12;
        if (inText) score += Math.min(8, e.xl.split(t).length - 1);
      }
      // Guides before generated reference pages, unless the title matches.
      if (e.s !== "Reference") score += 6;
      results.push({ e: e, score: score });
    });
    results.sort(function (a, b) { return b.score - a.score || a.e.t.length - b.e.t.length; });
    return results.slice(0, 20).map(function (r) { return r.e; });
  }

  function render() {
    var q = input.value.trim();
    if (!q) { box.hidden = true; return; }
    load().then(function () {
      var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
      var hits = search(q);
      active = -1;
      if (!hits.length) {
        box.innerHTML = '<div class="r-empty">No pages match “' + esc(q) + '”.</div>';
      } else {
        box.innerHTML = hits.map(function (e) {
          return '<a role="option" href="' + esc(e.u) + '"><span class="r-title">' + highlight(e.t, terms) +
            '</span><span class="r-section">' + esc(e.s) + '</span><span class="r-text">' +
            highlight(snippet(e, terms), terms) + "</span></a>";
        }).join("");
      }
      box.hidden = false;
    }).catch(function () {
      box.innerHTML = '<div class="r-empty">Search is not available right now.</div>';
      box.hidden = false;
    });
  }

  var timer;
  input.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(render, 80); });
  input.addEventListener("focus", function () { load(); if (input.value) render(); });
  input.addEventListener("keydown", function (e) {
    var links = box.querySelectorAll("a");
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (!links.length) return;
      e.preventDefault();
      active = (active + (e.key === "ArrowDown" ? 1 : -1) + links.length) % links.length;
      links.forEach(function (a, i) { a.classList.toggle("active", i === active); });
      links[active].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter") {
      var target = links[active >= 0 ? active : 0];
      if (target) { e.preventDefault(); window.location.href = target.href; }
    } else if (e.key === "Escape") {
      box.hidden = true;
      input.blur();
    }
  });
  document.addEventListener("click", function (e) {
    if (!e.target.closest(".search")) box.hidden = true;
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && document.activeElement !== input &&
        !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
      e.preventDefault();
      input.focus();
    }
  });
})();
