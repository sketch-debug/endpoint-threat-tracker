/* Dashboard extras: 7-day signal bar chart (no external libraries, offline). */
(function () {
  "use strict";
  function drawChart(canvas) {
    var values = [];
    var labels = [];
    try {
      values = JSON.parse(canvas.getAttribute("data-values") || "[]");
      labels = JSON.parse(canvas.getAttribute("data-labels") || "[]");
    } catch (e) { return; }
    var dpr = window.devicePixelRatio || 1;
    var width = canvas.clientWidth || 480;
    var height = canvas.height || 140;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    var max = Math.max.apply(null, values.concat([1]));
    var pad = 24;
    var barSpace = (width - pad * 2) / values.length;
    var barWidth = Math.min(46, barSpace * 0.62);
    ctx.font = "11px Segoe UI, Arial, sans-serif";
    for (var i = 0; i < values.length; i++) {
      var h = Math.round((values[i] / max) * (height - pad * 2));
      var x = pad + i * barSpace + (barSpace - barWidth) / 2;
      var y = height - pad - h;
      ctx.fillStyle = values[i] > 0 ? "#8b0000" : "#d9dce2";
      ctx.fillRect(x, y, barWidth, Math.max(h, 1));
      ctx.fillStyle = "#1c1e26";
      ctx.textAlign = "center";
      ctx.fillText(String(values[i]), x + barWidth / 2, y - 4);
      ctx.fillStyle = "#61666f";
      ctx.fillText((labels[i] || "").slice(5), x + barWidth / 2, height - 8);
    }
    ctx.strokeStyle = "#d9dce2";
    ctx.beginPath();
    ctx.moveTo(pad - 6, height - pad);
    ctx.lineTo(width - pad + 6, height - pad);
    ctx.stroke();
  }
  function init() {
    var charts = document.querySelectorAll("canvas[data-chart]");
    for (var i = 0; i < charts.length; i++) drawChart(charts[i]);
    // Destructive forms ask first; data-confirm keeps the handler out of
    // the markup so CSP can stay script-src 'self' with no inline scripts.
    var guarded = document.querySelectorAll("form[data-confirm]");
    for (var j = 0; j < guarded.length; j++) {
      (function (form) {
        form.addEventListener("submit", function (e) {
          if (!window.confirm(form.getAttribute("data-confirm"))) e.preventDefault();
        });
      })(guarded[j]);
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
