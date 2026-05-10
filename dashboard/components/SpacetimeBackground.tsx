"use client";

import { useEffect, useRef } from "react";

const VERT = `
attribute vec2 aPos;
varying vec2 vUv;
void main() {
  vUv = aPos * 0.5 + 0.5;
  gl_Position = vec4(aPos, 0.0, 1.0);
}
`;

const FRAG = `
precision highp float;
varying vec2 vUv;
uniform float uTime;
uniform vec2 uResolution;
uniform vec2 uMouse;
uniform float uActivity;

float hash(vec2 p) {
  p = fract(p * vec2(123.34, 456.21));
  p += dot(p, p + 45.32);
  return fract(p.x * p.y);
}

float vnoise(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  float a = hash(i);
  float b = hash(i + vec2(1.0, 0.0));
  float c = hash(i + vec2(0.0, 1.0));
  float d = hash(i + vec2(1.0, 1.0));
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(a, b, u.x), mix(c, d, u.x), u.y);
}

float fbm(vec2 p) {
  float v = 0.0;
  float a = 0.5;
  mat2 r = mat2(0.80, -0.60, 0.60, 0.80);
  for (int i = 0; i < 6; i++) {
    v += a * vnoise(p);
    p = r * p * 2.0;
    a *= 0.5;
  }
  return v;
}

float starLayer(vec2 uv, float t, float seed, float threshold) {
  vec2 i = floor(uv);
  vec2 f = fract(uv);
  float h = hash(i + seed);
  if (h < threshold) return 0.0;
  vec2 c = vec2(hash(i + seed + 1.7), hash(i + seed + 3.3));
  float d = length(f - c);
  float r = (h - threshold) / (1.0 - threshold);
  float size = 0.035 + 0.06 * r;
  float br = smoothstep(size, 0.0, d);

  // Per-star twinkle: each star has its own period, phase and floor brightness
  float twSpeed = 0.45 + 1.35 * fract(h * 91.7);
  float twPhase = h * 6.2831;
  float twWave  = sin(t * twSpeed + twPhase) * 0.5 + 0.5;
  float tw      = pow(twWave, 1.6);
  float minBr   = 0.05 + 0.45 * fract(h * 41.3);
  float amp     = mix(minBr, 1.0, tw);

  return br * amp * (0.55 + 0.45 * r);
}

vec2 warp(vec2 p, vec2 m, float k) {
  vec2 d = p - m;
  float r2 = dot(d, d);
  float pull = k / (r2 + 0.045);
  return p - d * pull;
}

void main() {
  vec2 uv = vUv;
  vec2 aspect = vec2(uResolution.x / max(uResolution.y, 1.0), 1.0);
  vec2 p = (uv - 0.5) * aspect;
  vec2 m = (uMouse - 0.5) * aspect;

  // Three depth layers — closer = stronger spacetime curvature
  vec2 pNear = warp(p, m, 0.085 * uActivity);
  vec2 pMid  = warp(p, m, 0.045 * uActivity);
  vec2 pFar  = warp(p, m, 0.018 * uActivity);

  // Nebula — two scales of FBM with paleta Andromeda
  vec2 nP = pMid * 1.35 + vec2(uTime * 0.011, uTime * 0.008);
  float n1 = fbm(nP);
  float n2 = fbm(nP * 1.85 + 17.0);
  float nebula  = pow(smoothstep(0.34, 0.86, n1), 1.7);
  float nebula2 = pow(smoothstep(0.55, 0.95, n2), 1.5) * 0.65;

  vec3 emberA = vec3(1.00, 0.30, 0.30);
  vec3 emberB = vec3(0.55, 0.10, 0.18);
  vec3 violet = vec3(0.18, 0.08, 0.28);
  vec3 nebulaCol = mix(violet, emberB, nebula);
  nebulaCol = mix(nebulaCol, emberA, nebula2);
  nebulaCol *= 0.42;

  // Starfield — three parallactic layers
  float s = 0.0;
  s += starLayer(pNear * 14.0 +  3.1, uTime, 0.0,  0.985) * 1.00;
  s += starLayer(pMid  * 28.0 + 11.7, uTime, 7.0,  0.990) * 0.70;
  s += starLayer(pFar  * 60.0 + 23.3, uTime, 19.0, 0.994) * 0.45;

  // Vignette
  float vig = smoothstep(1.05, 0.20, length(p));

  // Spacetime grid — bent by the nearest warp, only visible where nebula is dense
  vec2 g = pNear * 7.5;
  vec2 gf = abs(fract(g + 0.5) - 0.5);
  float line = 1.0 - smoothstep(0.0, 0.025, min(gf.x, gf.y));
  float grid = line * 0.028 * (0.15 + 0.85 * nebula) * vig;

  vec3 col = vec3(0.012, 0.014, 0.018);
  col += nebulaCol * vig;
  col += vec3(s);
  col += emberA * grid;

  // Subtle ember glow at gravity well center
  float mg = exp(-length(p - m) * 4.5) * 0.10 * uActivity;
  col += emberA * mg;

  gl_FragColor = vec4(col, 1.0);
}
`;

export function SpacetimeBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const gl = canvas.getContext("webgl", {
      antialias: false,
      alpha: false,
      powerPreference: "low-power",
      preserveDrawingBuffer: false,
    });
    if (!gl) return;

    const compile = (type: number, src: string): WebGLShader | null => {
      const sh = gl.createShader(type);
      if (!sh) return null;
      gl.shaderSource(sh, src);
      gl.compileShader(sh);
      if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
        gl.deleteShader(sh);
        return null;
      }
      return sh;
    };

    const vs = compile(gl.VERTEX_SHADER, VERT);
    const fs = compile(gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) return;

    const prog = gl.createProgram();
    if (!prog) return;
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      gl.deleteProgram(prog);
      return;
    }
    gl.useProgram(prog);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]),
      gl.STATIC_DRAW,
    );
    const aPos = gl.getAttribLocation(prog, "aPos");
    gl.enableVertexAttribArray(aPos);
    gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

    const uTime = gl.getUniformLocation(prog, "uTime");
    const uRes = gl.getUniformLocation(prog, "uResolution");
    const uMouse = gl.getUniformLocation(prog, "uMouse");
    const uActivity = gl.getUniformLocation(prog, "uActivity");

    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    const resize = () => {
      const w = Math.max(1, Math.floor(window.innerWidth * dpr));
      const h = Math.max(1, Math.floor(window.innerHeight * dpr));
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
        gl.viewport(0, 0, w, h);
      }
    };
    resize();
    window.addEventListener("resize", resize);

    const target = { x: 0.5, y: 0.5 };
    const current = { x: 0.5, y: 0.5 };
    let activity = 0;
    let lastMove = 0;
    const start = performance.now();
    let last = start;
    let frameId = 0;
    let running = true;

    const onMove = (e: MouseEvent) => {
      target.x = e.clientX / window.innerWidth;
      target.y = 1 - e.clientY / window.innerHeight;
      lastMove = performance.now();
    };
    window.addEventListener("mousemove", onMove, { passive: true });

    const draw = () => {
      if (!running) return;
      const now = performance.now();
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const t = (now - start) / 1000;

      const idle = lastMove === 0 || now - lastMove > 2000;
      if (idle) {
        target.x = 0.5 + 0.18 * Math.sin(t * 0.23);
        target.y = 0.5 + 0.13 * Math.cos(t * 0.31);
      }

      const k = Math.min(1, dt * 6);
      current.x += (target.x - current.x) * k;
      current.y += (target.y - current.y) * k;
      activity += (1 - activity) * Math.min(1, dt * 0.9);

      gl.uniform1f(uTime, t);
      gl.uniform2f(uRes, canvas.width, canvas.height);
      gl.uniform2f(uMouse, current.x, current.y);
      gl.uniform1f(uActivity, activity);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

      frameId = requestAnimationFrame(draw);
    };

    if (reduced) {
      gl.uniform1f(uTime, 0);
      gl.uniform2f(uRes, canvas.width, canvas.height);
      gl.uniform2f(uMouse, 0.5, 0.5);
      gl.uniform1f(uActivity, 0);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    } else {
      frameId = requestAnimationFrame(draw);
    }

    const onVis = () => {
      if (document.hidden) {
        running = false;
        cancelAnimationFrame(frameId);
      } else if (!reduced) {
        running = true;
        last = performance.now();
        frameId = requestAnimationFrame(draw);
      }
    };
    document.addEventListener("visibilitychange", onVis);

    return () => {
      running = false;
      cancelAnimationFrame(frameId);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMove);
      document.removeEventListener("visibilitychange", onVis);
      gl.deleteBuffer(buf);
      gl.deleteProgram(prog);
      gl.deleteShader(vs);
      gl.deleteShader(fs);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="fixed inset-0 w-screen h-screen pointer-events-none"
      style={{ zIndex: 0 }}
    />
  );
}

export default SpacetimeBackground;
