"use client";
import { useState, useRef } from "react";
import Link from "next/link";
import { ShieldAlert, Play, RotateCcw, Info } from "lucide-react";
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import { api } from "../../lib/api";

const SEVERITY_COLOR = {
  low: "#22c55e",
  medium: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
};

const SEVERITY_LABEL = {
  low: "Normal activity",
  medium: "Suspicious activity",
  high: "Likely ransomware",
  critical: "Ransomware detected",
};

const CHART_TOOLTIP_STYLE = { background: "#121826", border: "1px solid #1f2937", fontSize: 12 };

export default function DemoPage() {
  const [phase, setPhase] = useState("idle"); // idle | loading | running | done
  const [history, setHistory] = useState([]);
  const [current, setCurrent] = useState(null);
  const [log, setLog] = useState([]);
  const [featureImportance, setFeatureImportance] = useState([]);
  const [error, setError] = useState(null);
  const cancelRef = useRef(false);
  const lastSeverityRef = useRef(null);

  async function start() {
    setError(null);
    setHistory([]);
    setCurrent(null);
    setLog([]);
    lastSeverityRef.current = null;
    setPhase("loading");
    cancelRef.current = false;
    try {
      const session = await api.demoStart();
      setFeatureImportance(session.feature_importance || []);
      setPhase("running");
      await playTimeline(session.timeline);
      if (!cancelRef.current) setPhase("done");
    } catch (e) {
      setError(e.message);
      setPhase("idle");
    }
  }

  function narrate(point) {
    const f = point.features;
    if (lastSeverityRef.current !== point.severity) {
      lastSeverityRef.current = point.severity;
      if (point.severity === "medium") return `Step ${point.step}: activity pattern shifting — risk climbing to ${(point.risk_score * 100).toFixed(0)}%`;
      if (point.severity === "high") return `Step ${point.step}: write throughput spiking (${f.write_rate_mb_s} MB/s) — flagged likely ransomware`;
      if (point.severity === "critical") return `Step ${point.step}: sustained high-entropy writes (${f.entropy_mean}) — ransomware confirmed`;
      if (point.severity === "low") return `Step ${point.step}: activity back to baseline levels`;
    }
    return null;
  }

  async function playTimeline(timeline) {
    for (const point of timeline) {
      if (cancelRef.current) return;
      setCurrent(point);
      setHistory((h) => [
        ...h,
        {
          step: point.step,
          risk_score: point.risk_score,
          entropy_mean: point.features.entropy_mean,
          entropy_max: point.features.entropy_max,
          entropy_std: point.features.entropy_std,
          write_rate_mb_s: point.features.write_rate_mb_s,
          write_events_per_s: point.features.write_events_per_s,
          read_events_per_s: point.features.read_events_per_s,
        },
      ]);
      const note = narrate(point);
      if (note) setLog((l) => [...l, { step: point.step, text: note, severity: point.severity }]);
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  function reset() {
    cancelRef.current = true;
    setPhase("idle");
    setHistory([]);
    setCurrent(null);
    setLog([]);
    setError(null);
  }

  const running = phase === "running" || phase === "loading";

  return (
    <main className="min-h-screen bg-bg text-gray-100 px-6 py-8">
      <nav className="max-w-6xl mx-auto flex items-center justify-between mb-10">
        <Link href="/" className="flex items-center gap-2 font-bold">
          <ShieldAlert className="text-accent" size={20} /> RansomShield
        </Link>
        <a
          href="https://github.com/YOUR_USERNAME/ransomshield"
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-gray-400 hover:text-white transition"
        >
          View source
        </a>
      </nav>

      <div className="max-w-6xl mx-auto">
        <h1 className="text-2xl font-bold mb-2">Live simulated attack</h1>

        <div className="flex items-start gap-2 bg-panel border border-border rounded-lg px-4 py-3 mb-6 text-sm text-gray-400">
          <Info size={16} className="mt-0.5 shrink-0 text-gray-500" />
          <p>
            Click <strong className="text-gray-200">"Run simulated attack"</strong> below. Every
            data point here is a real row from actual ransomware training data (RanSAP), scored by
            the real trained model live — nothing is fabricated for this demo, and nothing on your
            device is touched.
          </p>
        </div>

        {error && (
          <div className="bg-red-950/40 border border-red-800 text-red-300 text-sm rounded-lg px-4 py-3 mb-6">
            {error}
          </div>
        )}

        <div className="flex items-center gap-3 mb-8">
          {!running && (
            <button
              onClick={start}
              className="flex items-center gap-2 bg-accent hover:bg-red-600 transition px-5 py-2.5 rounded-lg font-semibold"
            >
              <Play size={16} /> {phase === "done" ? "Run again" : "Run simulated attack"}
            </button>
          )}
          {phase === "loading" && <div className="text-sm text-gray-400">Scoring timeline...</div>}
          {phase === "running" && (
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <span className="w-2 h-2 rounded-full bg-accent2 animate-pulse" />
              Playing... step {history.length}/20
            </div>
          )}
          {phase === "done" && (
            <button
              onClick={reset}
              className="flex items-center gap-2 border border-border hover:border-gray-500 transition px-4 py-2.5 rounded-lg text-sm"
            >
              <RotateCcw size={14} /> Reset
            </button>
          )}
        </div>

        {/* Top row: risk score + current status */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <div className="md:col-span-2 min-w-0 bg-panel border border-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-gray-400 mb-4">Risk score over time</h2>
            {history.length === 0 ? (
              <div className="h-[240px] flex items-center justify-center text-sm text-gray-600">
                Run the simulation to see the chart build live.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={240}>
                <LineChart data={history}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="step" stroke="#6b7280" fontSize={12} />
                  <YAxis domain={[0, 1]} stroke="#6b7280" fontSize={12} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Line type="monotone" dataKey="risk_score" stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} name="Risk score" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="min-w-0 bg-panel border border-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-gray-400 mb-4">Current status</h2>
            {current ? (
              <div className="space-y-4">
                <div>
                  <div className="text-3xl font-bold" style={{ color: SEVERITY_COLOR[current.severity] }}>
                    {(current.risk_score * 100).toFixed(1)}%
                  </div>
                  <div
                    className="inline-block text-xs font-semibold mt-1 px-2 py-0.5 rounded"
                    style={{ color: SEVERITY_COLOR[current.severity], backgroundColor: `${SEVERITY_COLOR[current.severity]}20` }}
                  >
                    {SEVERITY_LABEL[current.severity]}
                  </div>
                </div>
                <div className="text-xs text-gray-500 space-y-1 pt-2 border-t border-border">
                  <div>model confidence: {(current.model_prob * 100).toFixed(1)}%</div>
                  <div>anomaly score: {(current.anomaly_score * 100).toFixed(1)}%</div>
                </div>
              </div>
            ) : (
              <p className="text-sm text-gray-600">Nothing running yet.</p>
            )}
          </div>
        </div>

        {/* Middle row: entropy + storage activity */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div className="min-w-0 bg-panel border border-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-gray-400 mb-4">Data randomness (entropy)</h2>
            {history.length === 0 ? (
              <div className="h-[200px] flex items-center justify-center text-sm text-gray-600">No data yet.</div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={history}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="step" stroke="#6b7280" fontSize={11} />
                  <YAxis domain={[0, 1]} stroke="#6b7280" fontSize={11} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Line type="monotone" dataKey="entropy_mean" stroke="#38bdf8" strokeWidth={2} dot={false} isAnimationActive={false} name="Avg." />
                  <Line type="monotone" dataKey="entropy_max" stroke="#818cf8" strokeWidth={1.5} dot={false} isAnimationActive={false} name="Peak" />
                  <Line type="monotone" dataKey="entropy_std" stroke="#a78bfa" strokeWidth={1.5} dot={false} isAnimationActive={false} name="Volatility" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="min-w-0 bg-panel border border-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-gray-400 mb-4">Storage activity</h2>
            {history.length === 0 ? (
              <div className="h-[200px] flex items-center justify-center text-sm text-gray-600">No data yet.</div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={history}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="step" stroke="#6b7280" fontSize={11} />
                  <YAxis stroke="#6b7280" fontSize={11} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Line type="monotone" dataKey="write_events_per_s" stroke="#fb923c" strokeWidth={2} dot={false} isAnimationActive={false} name="Writes/s" />
                  <Line type="monotone" dataKey="read_events_per_s" stroke="#facc15" strokeWidth={1.5} dot={false} isAnimationActive={false} name="Reads/s" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Bottom row: feature importance + event log */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="min-w-0 bg-panel border border-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-gray-400 mb-1">What the model actually weighs</h2>
            <p className="text-xs text-gray-600 mb-4">Real feature importance from the trained model, not illustrative.</p>
            {featureImportance.length === 0 ? (
              <div className="h-[220px] flex items-center justify-center text-sm text-gray-600">Run the simulation to load this.</div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={featureImportance} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
                  <XAxis type="number" stroke="#6b7280" fontSize={11} />
                  <YAxis type="category" dataKey="label" stroke="#6b7280" fontSize={11} width={130} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="importance" fill="#ef4444" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="min-w-0 bg-panel border border-border rounded-xl p-5">
            <h2 className="text-sm font-medium text-gray-400 mb-4">Detection log</h2>
            {log.length === 0 ? (
              <div className="h-[220px] flex items-center justify-center text-sm text-gray-600">Events will appear here as the attack unfolds.</div>
            ) : (
              <div className="h-[220px] overflow-y-auto space-y-2">
                {log.map((entry, i) => (
                  <div key={i} className="text-xs border-l-2 pl-3 py-0.5" style={{ borderColor: SEVERITY_COLOR[entry.severity] }}>
                    <span className="text-gray-300">{entry.text}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {phase === "done" && (
          <div className="mt-6 bg-panel border border-border rounded-xl p-5 text-sm text-gray-400">
            That's the full picture: real telemetry, scored moment-by-moment by the real trained
            model, without knowing the file name or malware family in advance.{" "}
            <a
              href="https://github.com/YOUR_USERNAME/ransomshield"
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline"
            >
              See how it's built on GitHub →
            </a>
          </div>
        )}
      </div>
    </main>
  );
}
