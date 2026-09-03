"use client";
import Link from "next/link";
import { ShieldAlert, Activity, Zap, Github } from "lucide-react";

export default function Home() {
  return (
    <main className="min-h-screen bg-bg text-gray-100">
      <nav className="flex items-center justify-between px-8 py-5 border-b border-border">
        <div className="flex items-center gap-2 font-bold text-lg">
          <ShieldAlert className="text-accent" size={22} />
          RansomShield
        </div>
        <a
          href="https://github.com/Vedansh-Gupta-VG/ransomshield"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-white transition"
        >
          <Github size={16} /> View source
        </a>
      </nav>

      <section className="max-w-4xl mx-auto text-center px-6 pt-24 pb-16">
        <div className="inline-flex items-center gap-2 bg-panel border border-border rounded-full px-4 py-1.5 text-xs text-gray-400 mb-6">
          <span className="w-2 h-2 rounded-full bg-accent2 animate-pulse" />
          ML-powered behavioral detection — live
        </div>
        <h1 className="text-5xl font-bold tracking-tight mb-6">
          Catch ransomware<br />before it finishes encrypting.
        </h1>
        <p className="text-gray-400 text-lg max-w-2xl mx-auto mb-10">
          RansomShield watches storage behavior in real time — entropy shifts, write bursts,
          access patterns — and scores every signal through a model trained on real
          ransomware traces. No signatures. No waiting for a vendor update.
        </p>
        <div className="flex items-center justify-center gap-4">
          <Link
            href="/demo"
            className="bg-accent hover:bg-red-600 transition text-white px-6 py-3 rounded-lg font-semibold"
          >
            Watch a live attack get detected →
          </Link>
        </div>
        <p className="text-xs text-gray-600 mt-4">
          No install, no signup, zero cost — this is a self-contained live demo.
        </p>
      </section>

      <section className="max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-6 px-6 pb-24">
        <FeatureCard
          icon={<Activity size={20} className="text-accent2" />}
          title="Real behavioral ML"
          desc="Trained on real ransomware storage traces (RanSAP), not signature databases. Detects novel variants by behavior, not by name."
        />
        <FeatureCard
          icon={<Zap size={20} className="text-yellow-400" />}
          title="Sub-second scoring"
          desc="Every telemetry batch is scored the moment it arrives — entropy, I/O rate, event bursts — no batch delay."
        />
        <FeatureCard
          icon={<ShieldAlert size={20} className="text-accent" />}
          title="Nothing fabricated"
          desc="Every number in the demo is a real row from real training data, scored live by the real trained model — not a scripted animation."
        />
      </section>
    </main>
  );
}

function FeatureCard({ icon, title, desc }) {
  return (
    <div className="bg-panel border border-border rounded-xl p-6">
      <div className="mb-3">{icon}</div>
      <h3 className="font-semibold mb-2">{title}</h3>
      <p className="text-sm text-gray-400 leading-relaxed">{desc}</p>
    </div>
  );
}
