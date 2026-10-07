"use client";

import { useEffect, useRef, useState } from "react";

export default function Home() {
  const [playing, setPlaying] = useState(false);
  const [score, setScore] = useState(0);
  const [missed, setMissed] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!playing) return;
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    let paddle = 180, x = 240, y = 180, vx = 3, vy = 3, frame = 0, hits = 0;
    const move = (event: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      paddle = Math.max(0, Math.min(380, (event.clientX - rect.left) * 480 / rect.width - 50));
    };
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
        event.preventDefault();
        paddle = Math.max(0, Math.min(380, paddle + (event.key === "ArrowLeft" ? -30 : 30)));
      }
    };
    const draw = () => {
      x += vx; y += vy;
      if (x < 8 || x > 472) vx *= -1;
      if (y < 8) vy *= -1;
      if (vy > 0 && y >= 302 && y <= 314 && x >= paddle && x <= paddle + 100) {
        vy = -Math.abs(vy) - 0.15; hits++; setScore(hits);
      }
      ctx.fillStyle = "#174e43"; ctx.fillRect(0, 0, 480, 340);
      ctx.strokeStyle = "#ffffff40"; ctx.setLineDash([8, 8]); ctx.beginPath(); ctx.moveTo(0,170); ctx.lineTo(480,170); ctx.stroke();
      ctx.fillStyle = "#d7ef6a"; ctx.fillRect(paddle, 312, 100, 10);
      ctx.fillStyle = "#fff8e8"; ctx.beginPath(); ctx.arc(x, y, 8, 0, Math.PI * 2); ctx.fill();
      if (y > 350) { setPlaying(false); setMissed(true); return; }
      frame = requestAnimationFrame(draw);
    };
    canvas.addEventListener("pointermove", move);
    window.addEventListener("keydown", keyboard);
    frame = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(frame); canvas.removeEventListener("pointermove", move); window.removeEventListener("keydown", keyboard); };
  }, [playing]);

  const start = () => { setScore(0); setMissed(false); setPlaying(true); };

  return (
    <main>
      <header className="nav">
        <a className="brand" href="#" aria-label="Rally home"><span className="brand-icon">◒</span> rally<span className="brand-dot">.</span></a>
        <nav aria-label="Main navigation"><a href="#how-to-play">How to play</a><button className="nav-play" onClick={start}>Let’s play <span>↗</span></button></nav>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow"><span /> SMALL BREAK. BIG ENERGY.</div>
          <h1>Life’s better<br />with a little<br /><em>back & forth.</em></h1>
          <p>A paddle. A ball. A little friendly competition.<br className="desktop-break" /> Step away from the everyday and get into the game.</p>
          <button className="primary" onClick={start}>Play a quick game <span>↗</span></button>
          <div className="play-note"><span>✦</span> Free to play. Just bring your reflexes.</div>
        </div>
        <div className="hero-art" aria-label="Illustration of a ping-pong table and paddles">
          <div className="orbit orbit-one" /><div className="orbit orbit-two" />
          <span className="art-caption">GOOD TIMES, ON REPEAT.</span>
          <div className="table"><div className="table-line" /><div className="net" /><div className="table-label">rally.</div></div>
          <div className="paddle paddle-coral"><div className="handle" /><div className="paddle-face" /></div>
          <div className="paddle paddle-lime"><div className="handle" /><div className="paddle-face" /></div>
          <div className="ball" /><div className="ball-trail" />
          <span className="spark spark-one">✳</span><span className="spark spark-two">✦</span>
          <div className="art-sticker">ONE MORE<br /><strong>ROUND?</strong></div>
        </div>
      </section>

      <div className="ticker" aria-hidden="true"><span>LESS SCROLLING</span><b>✳</b><span>MORE RALLYING</span><b>✳</b><span>FIND YOUR FLOW</span><b>✳</b><span>MAKE YOUR BREAK</span><b>✳</b></div>

      <section className="how" id="how-to-play">
        <div className="section-heading"><span className="eyebrow">READY, SET, RALLY.</span><h2>Easy to pick up.<br />Hard to put down.</h2><p>No downloads. No setup. Just a little hand-eye coordination and a good time.</p></div>
        <div className="steps">
          <article><span className="step-number">01 /</span><h3>Grab your paddle</h3><p>Hit play and you’re in. Your next five-minute break just got a whole lot better.</p></article>
          <article><span className="step-number">02 /</span><h3>Find your rhythm</h3><p>Move your mouse, swipe your finger, or use the arrow keys to keep the ball in play.</p></article>
          <article><span className="step-number">03 /</span><h3>Keep it going</h3><p>Every return counts. Beat your score, find your flow, and go for one more round.</p></article>
        </div>
      </section>
      <footer><a className="brand" href="#">rally.</a><span>Made for the love of the game.</span><span>See you at the table ↗</span></footer>

      {(playing || missed) && <div className="modal-backdrop"><section className="game-modal" role="dialog" aria-modal="true" aria-labelledby="game-title"><div className="game-header"><h2 id="game-title">{missed ? "Nice rally!" : "Keep the rally alive."}</h2><button aria-label="Close game" autoFocus onClick={() => {setPlaying(false);setMissed(false);}}>✕</button></div><p aria-live="polite">{score} {score === 1 ? "return" : "returns"} · Mouse, touch, or arrow keys</p>{playing ? <canvas ref={canvasRef} width={480} height={340} aria-label="Ping-pong practice game" /> : <div className="game-end"><span>✳</span><p>There’s always another round.</p><button className="primary" onClick={start}>Play again ↗</button></div>}</section></div>}
    </main>
  );
}
