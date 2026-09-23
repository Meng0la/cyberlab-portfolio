import { useState } from "react";
import { supabase } from "./lib/supabase.js";
import logo from "./assets/logo.png";

const INPUT = "bg-cyber-bg border border-cyber-border rounded-md text-cyber-text px-3 py-2 text-[13px] w-full font-mono outline-none box-border";
const LABEL = "text-[11px] text-cyber-muted mb-1 block";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const { error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) throw error;
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen text-cyber-text font-mono flex items-center justify-center">
      <form onSubmit={submit} className="bg-cyber-surface border border-cyber-border rounded-lg p-4 w-[340px] overflow-hidden">
        <div className="flex gap-1.5 -mx-4 -mt-4 mb-5 px-3 py-2 bg-black/30 border-b border-cyber-border">
          <span className="w-2.5 h-2.5 rounded-full bg-cyber-danger inline-block" />
          <span className="w-2.5 h-2.5 rounded-full bg-cyber-warning inline-block" />
          <span className="w-2.5 h-2.5 rounded-full bg-cyber-accent inline-block" />
        </div>
        <div className="flex items-center gap-2.5 mb-5">
          <img src={logo} alt="CyberLab" className="w-8 h-8 rounded-lg object-cover animate-pulse-glow" />
          <div className="text-[15px] font-extrabold text-cyber-accent tracking-widest [text-shadow:0_0_12px_rgba(220,38,38,0.6)]">CYBERLAB</div>
        </div>

        <div>
          <label className={LABEL}>E-mail</label>
          <input className={INPUT} type="email" required value={email} onChange={e => setEmail(e.target.value)} />
        </div>
        <div className="mt-3">
          <label className={LABEL}>Senha</label>
          <input className={INPUT} type="password" required minLength={6} value={password} onChange={e => setPassword(e.target.value)} />
        </div>

        {error && <div className="text-cyber-danger text-xs mt-3">{error}</div>}

        <button type="submit" disabled={busy} className="border-none text-white px-4 py-2 rounded-md text-xs font-mono font-bold cursor-pointer tracking-wide bg-cyber-accent w-full mt-4">
          ENTRAR
        </button>
      </form>
    </div>
  );
}
