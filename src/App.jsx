import { useEffect, useState } from 'react';
import { supabase } from './lib/supabase.js';
import CyberLabDashboard from './CyberLabDashboard.jsx';
import Login from './Login.jsx';

function App() {
  const [session, setSession] = useState(undefined); // undefined = ainda carregando

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setSession(data.session));
    const { data: subscription } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
    });
    return () => subscription.subscription.unsubscribe();
  }, []);

  if (session === undefined) {
    return (
      <div className="min-h-screen flex items-center justify-center text-cyber-accent font-mono">
        Carregando<span className="animate-blink">_</span>
      </div>
    );
  }

  if (!session) return <Login />;

  return <CyberLabDashboard />;
}

export default App;
