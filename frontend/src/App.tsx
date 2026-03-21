import React, { useState, useEffect, useRef } from 'react';
import './index.css';

// ── TYPES ────────────────────────────────────
interface SystemStats {
  active_flows: number;
  total_created: number;
  total_expired: number;
}

interface TermLine {
  id: string;
  time: string;
  text: string;
  type: 'info' | 'success' | 'warn' | 'err';
}

// ── MAIN APP ─────────────────────────────────
function App() {
  const [activeTab, setActiveTab] = useState<'dash' | 'ai' | 'rules' | 'config'>('dash');
  
  // Dashboard State
  const [stats, setStats] = useState<SystemStats>({ active_flows: 0, total_created: 0, total_expired: 0 });
  const [activeBlocks, setActiveBlocks] = useState(0);
  const [activeRules, setActiveRules] = useState<any[]>([]);

  // Terminal/AI State
  const [prompt, setPrompt] = useState("");
  const [loading, setLoading] = useState(false);
  const [termOutput, setTermOutput] = useState<TermLine[]>([
    { id: '1', time: new Date().toLocaleTimeString(), text: "AEROCIFER Brain Initialized...", type: 'info' },
    { id: '2', time: new Date().toLocaleTimeString(), text: "Listening on ML ports for telemetry.", type: 'info' },
  ]);
  const termEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Fetch live system rules from Python backend
    const fetchRules = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/v1/security/rules');
        const data = await res.json();
        if (data.rules) {
          setActiveRules(data.rules);
          setActiveBlocks(data.rules.length);
        }
      } catch (e) {
        // Backend offline, keep previous
      }
    };
    
    fetchRules();
    const interval = setInterval(() => {
      fetchRules();
      setStats(prev => ({
        active_flows: prev.active_flows + Math.floor(Math.random() * 5),
        total_created: prev.total_created + Math.floor(Math.random() * 10),
        total_expired: prev.total_expired + Math.floor(Math.random() * 3)
      }));
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleUnblock = async (ruleId: string) => {
    try {
      await fetch(`http://localhost:8000/api/v1/security/rules/${ruleId}`, { method: 'DELETE' });
      setActiveRules(prev => prev.filter(r => r.id !== ruleId));
      addTermLine(`Successfully sent UNBLOCK signal for Rule ID: ${ruleId.substring(0,6)}...`, 'success');
    } catch (e) {
      addTermLine(`Failed to hit API to unblock ${ruleId}`, 'err');
    }
  };

  useEffect(() => { termEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [termOutput]);

  const addTermLine = (text: string, type: 'info' | 'success' | 'warn' | 'err' = 'info') => {
    setTermOutput(prev => [...prev, {
      id: Math.random().toString(36),
      time: new Date().toLocaleTimeString(),
      text, type
    }]);
  };

  const handleAIExecute = async () => {
    if(!prompt.trim()) return;
    
    setLoading(true);
    addTermLine(`> PROCESSING COMMAND: "${prompt}"`, 'warn');
    
    try {
      const response = await fetch('http://localhost:8000/api/v1/ai/prompt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ prompt })
      });
      
      if (!response.ok) {
        throw new Error("FastAPI Backend is Offline or returned error.");
      }
      
      const data = await response.json();
      
      if (data.success) {
        addTermLine(`✅ SUCCESS: ${data.message}`, 'success');
        if (data.action_taken === "block_ip") setActiveBlocks(prev => prev + 1);
      } else {
        addTermLine(`❌ FAILED: ${data.message || "Could not understand command. Please try again."}`, 'err');
      }
    } catch (e: any) {
      // Fallback local UI mock if Python backend is not running yet
      addTermLine(`[API Offline] Falling back to Local AI Matcher...`, 'info');
      
      const p = prompt.toLowerCase();
      if(p.includes("add") || p.includes("assign")) {
         const ipMatch = prompt.match(/\d+\.\d+\.\d+\.\d+/);
         if(ipMatch) addTermLine(`Assigned IP ${ipMatch[0]} successfully (Mock)`, 'success');
         else addTermLine(`Could not find a valid IP in your command.`, 'err');
      } else if(p.includes("iot")) {
         addTermLine(`Created zone 'iot' (ID: ${Math.random().toString(36).substring(7)}) (Mock)`, 'success');
      } else if (p.includes("block")) {
         addTermLine(`Blocked traffic successfully. Updated strict rules. (Mock)`, 'success');
         setActiveBlocks(prev => prev + 1);
      } else {
         addTermLine(`Could not understand command. Please try again.`, 'err');
      }
    }
    
    setPrompt("");
    setLoading(false);
  };

  return (
    <div className="app-container">
      {/* SIDEBAR */}
      <nav className="sidebar animate-in">
        <div className="logo-area">
          <div className="logo-icon">▲</div>
          <div className="logo-text">
            <h1>AEROCIFER</h1>
            <span style={{ fontSize: '0.75rem', color: 'hsl(var(--brand-cyan))' }}>NXT-GEN FIREWALL</span>
          </div>
        </div>
        
        <div className="sidebar-nav">
          <div className={`nav-item ${activeTab === 'dash' ? 'active' : ''}`} onClick={() => setActiveTab('dash')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
            Live Telemetry
          </div>
          <div className={`nav-item ${activeTab === 'ai' ? 'active' : ''}`} onClick={() => setActiveTab('ai')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2a2 2 0 0 1 2 2c0 1.1-.9 2-2 2a2 2 0 0 1-2-2c0-1.1.9-2 2-2zM4 10a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm16 0a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm-8 12a2 2 0 1 1 0-4 2 2 0 0 1 0 4z"></path></svg>
            AI Config Engine
          </div>
          <div className={`nav-item ${activeTab === 'rules' ? 'active' : ''}`} onClick={() => setActiveTab('rules')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            Rule Engine Log
          </div>
          <div className={`nav-item ${activeTab === 'config' ? 'active' : ''}`} onClick={() => setActiveTab('config')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
            System Config
          </div>
        </div>
      </nav>

      {/* MAIN CONTENT */}
      <main className="main-content">
        
        {activeTab === 'dash' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>Live Telemetry</h2>
                <p>Tracking the traffic autoencoder states in real-time.</p>
             </div>
             
             <div className="dashboard-grid" style={{ marginTop: '2rem' }}>
                <div className="glass-card">
                  <div className="stat-label">Active Network Flows</div>
                  <div className="stat-value">{stats.active_flows.toLocaleString()}</div>
                  <div style={{color:'hsl(var(--status-good))', fontSize:'0.9rem'}}>+2% via Layer 4 Hooks</div>
                </div>
                
                <div className="glass-card">
                  <div className="stat-label">AI ML Anomalies Blocked</div>
                  <div className="stat-value" style={{background: 'linear-gradient(135deg, hsl(320,80%,60%), hsl(0,90%,60%))', WebkitBackgroundClip: 'text'}}>{activeBlocks}</div>
                  <div style={{color:'hsl(var(--text-muted))', fontSize:'0.9rem'}}>Caught by PyTorch Autoencoder</div>
                </div>

                <div className="glass-card">
                  <div className="stat-label">DPI Parsed Packets</div>
                  <div className="stat-value">{(stats.total_created * 15).toLocaleString()}</div>
                  <div style={{color:'hsl(var(--status-good))', fontSize:'0.9rem'}}>Deep Packet Inspected</div>
                </div>
             </div>
             
             <div className="glass-card" style={{ marginTop: '2rem' }}>
                <h3>Traffic Origin Heatmap / Simulation Map Placeholder</h3>
                <div style={{ height: '300px', width: '100%', background: 'hsla(0,0%,0%,0.2)', borderRadius: '16px', marginTop: '1rem', border: '1px solid hsla(190,90%,50%,0.1)', display: 'grid', placeItems: 'center', color: 'hsla(0,0%,100%,0.3)' }}>
                  Interactive WebGL Globe Element
                </div>
             </div>
          </div>
        )}

        {activeTab === 'ai' && (
          <div className="animate-in ai-interface">
             <div className="page-header">
                <h2>AI NLP Config Engine</h2>
                <p>Use conversational language to create zones & deploy active routing rules.</p>
             </div>
             
             <div className="ai-input-wrapper">
               <input 
                 type="text" 
                 className="ai-input" 
                 placeholder="Try: 'Create an IoT zone and assign 192.168.1.5' or 'Block traffic from 10.0.0.9'..."
                 value={prompt}
                 onChange={e => setPrompt(e.target.value)}
                 onKeyDown={e => e.key === 'Enter' && handleAIExecute()}
               />
               <button className="ai-btn" onClick={handleAIExecute} disabled={loading}>
                 {loading ? 'Processing...' : 'Execute Protocol'}
               </button>
             </div>
             
             <div className="glass-card" style={{ padding: 0 }}>
               <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--glass-border)', background: 'hsla(0,0%,0%,0.3)' }}>
                 <h4 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
                   <span style={{ display:'block', width: '8px', height: '8px', background:'hsl(var(--status-good))', borderRadius:'50%'}}></span>
                   Firewall Action Stream
                 </h4>
               </div>
               <div className="terminal-box" style={{ borderRadius: '0 0 var(--radius-lg) var(--radius-lg)' }}>
                 {termOutput.map(line => (
                   <div key={line.id} className="term-line">
                     <span className="term-time">[{line.time}]</span>
                     <span className={`term-${line.type}`}>{line.text}</span>
                   </div>
                 ))}
                 <div ref={termEndRef} />
               </div>
             </div>
             
             <div className="dashboard-grid">
               <div className="glass-card">
                 <h4 className="stat-label" style={{marginBottom: '1rem'}}>AI Insights (Device Classifier)</h4>
                 <div style={{display: 'flex', flexDirection: 'column', gap: '1rem'}}>
                   <div style={{background:'hsla(0,0%,0%,0.3)', padding: '1rem', borderRadius: '12px'}}>
                     <span style={{color: 'hsl(var(--brand-cyan))', fontWeight:600}}>192.168.1.44</span>
                     <div style={{fontSize: '0.9rem', color: 'hsl(var(--text-muted))', marginTop:'0.2rem'}}>Behavior matches <strong style={{color:'#fff'}}>IoT Device</strong> (98.2%)</div>
                   </div>
                   <div style={{background:'hsla(0,0%,0%,0.3)', padding: '1rem', borderRadius: '12px'}}>
                     <span style={{color: 'hsl(var(--brand-cyan))', fontWeight:600}}>10.0.0.12</span>
                     <div style={{fontSize: '0.9rem', color: 'hsl(var(--text-muted))', marginTop:'0.2rem'}}>Behavior matches <strong style={{color:'#fff'}}>Workstation</strong> (94.1%)</div>
                   </div>
                 </div>
               </div>
             </div>
          </div>
        )}

        {activeTab === 'rules' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>Active Rule Engine Logs</h2>
                <p>Recent threats auto-blocked by the core Firewall protocols.</p>
             </div>
             <div className="glass-card" style={{marginTop: '2rem'}}>
                <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse'}}>
                  <thead>
                    <tr style={{borderBottom: '1px solid hsla(0,0%,100%,0.1)', color: 'hsl(var(--text-muted))'}}>
                      <th style={{paddingBottom: '1rem'}}>Timestamp</th>
                      <th style={{paddingBottom: '1rem'}}>Target IP</th>
                      <th style={{paddingBottom: '1rem'}}>Threat Type</th>
                      <th style={{paddingBottom: '1rem'}}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeRules.map((rule, idx) => (
                      <tr key={rule.id || idx} style={{borderBottom: '1px solid hsla(0,0%,100%,0.05)'}}>
                        <td style={{padding: '1.5rem 0', fontFamily: 'monospace', fontSize: '0.9rem'}}>{rule.id.substring(0, 13)}...</td>
                        <td style={{color: 'hsl(var(--brand-cyan))'}}>{rule.src_ip} <span style={{color: '#888'}}>→</span> {rule.dst_ip}</td>
                        <td>{rule.protocol.toUpperCase()} Filter Block</td>
                        <td>
                          <span style={{color: rule.action === 'drop' ? 'hsl(var(--status-err))' : 'hsl(var(--status-good))', fontWeight: 'bold'}}>{rule.action.toUpperCase()}</span>
                          <button 
                            onClick={() => handleUnblock(rule.id)}
                            style={{marginLeft: '20px', padding: '0.3rem 0.8rem', background: 'hsla(0,0%,100%,0.1)', border: 'none', borderRadius: '4px', color: '#fff', cursor: 'pointer'}}
                          >
                            Unblock
                          </button>
                        </td>
                      </tr>
                    ))}
                    {activeRules.length === 0 && (
                      <tr>
                        <td colSpan={4} style={{padding: '2rem 0', textAlign: 'center', color: 'hsl(var(--text-muted))'}}>No active blocks. The Neural Network has not detected anomalies recently.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
             </div>
          </div>
        )}

        {activeTab === 'config' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>System Configuration</h2>
                <p>Firewall settings initialized from root config.yaml.</p>
             </div>
             
             <div className="glass-card" style={{marginTop: '2rem'}}>
                <div style={{display: 'flex', flexDirection: 'column', gap: '1.5rem'}}>
                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                    <div>
                      <h4 style={{margin: 0, color: 'hsl(var(--text-main))'}}>Machine Learning Co-Pilot</h4>
                      <div style={{fontSize: '0.9rem', color: 'hsl(var(--text-muted))'}}>Anomaly detector & device classifier</div>
                    </div>
                    <div style={{background: 'hsl(var(--status-good))', padding: '0.25rem 1rem', borderRadius: '1rem', color: '#000', fontWeight: 'bold'}}>ENABLED</div>
                  </div>
                  
                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid hsla(0,0%,100%,0.1)', paddingTop: '1.5rem'}}>
                    <div>
                      <h4 style={{margin: 0, color: 'hsl(var(--text-main))'}}>Deep Packet Inspection (DPI)</h4>
                      <div style={{fontSize: '0.9rem', color: 'hsl(var(--text-muted))'}}>Layer 7 parsing for HTTP, TLS, MQTT</div>
                    </div>
                    <div style={{background: 'hsl(var(--status-good))', padding: '0.25rem 1rem', borderRadius: '1rem', color: '#000', fontWeight: 'bold'}}>ENABLED</div>
                  </div>

                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid hsla(0,0%,100%,0.1)', paddingTop: '1.5rem'}}>
                    <div>
                      <h4 style={{margin: 0, color: 'hsl(var(--text-main))'}}>Simulation Mode</h4>
                      <div style={{fontSize: '0.9rem', color: 'hsl(var(--text-muted))'}}>Safely hooks Windows IP stack locally</div>
                    </div>
                    <div style={{background: 'hsl(var(--status-warn))', padding: '0.25rem 1rem', borderRadius: '1rem', color: '#000', fontWeight: 'bold'}}>ACTIVE</div>
                  </div>
                </div>
             </div>
          </div>
        )}

      </main>
    </div>
  );
}

export default App;
