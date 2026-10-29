(function () {
  var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var host = document.querySelector('.bg-effects');
  if (!host) return;

  var canvas = document.createElement('canvas');
  canvas.id = 'dc-bg-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  host.appendChild(canvas);

  var ctx = canvas.getContext('2d');
  var W = 0;
  var H = 0;
  var nodes = [];
  var meteors = [];
  var running = false;
  var rafId = null;

  var mouse = { x: -9999, y: -9999 };
  var LINK_DIST = 130;
  var MOUSE_DIST = 170;

  function resize() {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = host.clientWidth || window.innerWidth;
    H = host.clientHeight || window.innerHeight;
    canvas.width = Math.floor(W * dpr);
    canvas.height = Math.floor(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seedNodes();
  }

  function seedNodes() {
    var density = (W * H) / 26000;
    var count = Math.round(Math.max(26, Math.min(72, density)));
    nodes = [];
    for (var i = 0; i < count; i++) {
      nodes.push({
        x: Math.random() * W,
        y: Math.random() * H,
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
        r: Math.random() * 1.5 + 0.7,
        hue: Math.random()
      });
    }
  }

  function lerpColor(t, alpha) {
    var cr = Math.round(0 + (168 - 0) * t);
    var cg = Math.round(240 + (85 - 240) * t);
    var cb = Math.round(255 + (247 - 255) * t);
    return 'rgba(' + cr + ',' + cg + ',' + cb + ',' + alpha + ')';
  }

  function spawnMeteor() {
    if (meteors.length >= 2) return;
    meteors.push({
      x: W * 0.15 + Math.random() * W * 0.75,
      y: -30,
      vx: -(2.2 + Math.random() * 2.2),
      vy: 2.2 + Math.random() * 2.2,
      life: 1
    });
  }

  function step() {
    var i, j, a, b, dx, dy, d;

    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      a.x += a.vx;
      a.y += a.vy;

      dx = a.x - mouse.x;
      dy = a.y - mouse.y;
      d = Math.sqrt(dx * dx + dy * dy);
      if (d < MOUSE_DIST && d > 0.001) {
        var pull = (1 - d / MOUSE_DIST) * 0.35;
        a.x -= (dx / d) * pull;
        a.y -= (dy / d) * pull;
      }

      if (a.x < -20) a.x = W + 20;
      if (a.x > W + 20) a.x = -20;
      if (a.y < -20) a.y = H + 20;
      if (a.y > H + 20) a.y = -20;
    }

    ctx.clearRect(0, 0, W, H);

    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      for (j = i + 1; j < nodes.length; j++) {
        b = nodes[j];
        dx = a.x - b.x;
        dy = a.y - b.y;
        if (Math.abs(dx) > LINK_DIST || Math.abs(dy) > LINK_DIST) continue;
        d = Math.sqrt(dx * dx + dy * dy);
        if (d < LINK_DIST) {
          var strength = 1 - d / LINK_DIST;
          ctx.strokeStyle = lerpColor((a.hue + b.hue) / 2, strength * 0.28);
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      dx = a.x - mouse.x;
      dy = a.y - mouse.y;
      var md = Math.sqrt(dx * dx + dy * dy);
      var near = md < MOUSE_DIST;
      var alpha = near ? 0.9 : 0.55;
      var radius = a.r * (near ? 1.6 : 1);

      ctx.beginPath();
      ctx.fillStyle = lerpColor(a.hue, alpha);
      ctx.arc(a.x, a.y, radius, 0, Math.PI * 2);
      ctx.fill();

      if (near) {
        ctx.strokeStyle = 'rgba(103, 232, 249,' + ((1 - md / MOUSE_DIST) * 0.45) + ')';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.stroke();
      }
    }

    for (i = meteors.length - 1; i >= 0; i--) {
      var m = meteors[i];
      m.x += m.vx;
      m.y += m.vy;
      m.life -= 0.008;

      var tailX = m.x - m.vx * 14;
      var tailY = m.y - m.vy * 14;
      var grad = ctx.createLinearGradient(m.x, m.y, tailX, tailY);
      grad.addColorStop(0, 'rgba(190, 250, 255,' + (0.75 * m.life) + ')');
      grad.addColorStop(1, 'rgba(168, 85, 247, 0)');
      ctx.strokeStyle = grad;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(m.x, m.y);
      ctx.lineTo(tailX, tailY);
      ctx.stroke();

      if (m.life <= 0 || m.x < -60 || m.y > H + 60) meteors.splice(i, 1);
    }

    if (Math.random() < 0.005) spawnMeteor();
  }

  function loop() {
    if (!running) return;
    step();
    rafId = requestAnimationFrame(loop);
  }

  function start() {
    if (running) return;
    running = true;
    rafId = requestAnimationFrame(loop);
  }

  function stop() {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
  }

  window.addEventListener('resize', resize);

  window.addEventListener('pointermove', function (e) {
    var rect = canvas.getBoundingClientRect();
    mouse.x = e.clientX - rect.left;
    mouse.y = e.clientY - rect.top;
  });

  window.addEventListener('pointerleave', function () {
    mouse.x = -9999;
    mouse.y = -9999;
  });

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stop();
    else if (!reducedMotion) start();
  });

  resize();

  if (reducedMotion) {
    step();
  } else {
    start();
  }
})();
