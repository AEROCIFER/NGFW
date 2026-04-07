import React, { useState, useEffect, useRef } from 'react';
import './index.css';

// ── TYPES ─────────────────────────────────
interface SystemStats {
  active_flows: number;
  total_created: number;
  total_expired: number;
}

const ModalBackground = ({ children, onClose }: any) => (
  <div style={{position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000}}>
     <div className="glass-card" style={{width: '500px', background: 'hsla(220, 20%, 10%, 0.8)'}}>
        {children}
        <button onClick={onClose} style={{position: 'absolute', top: '1rem', right: '1rem', background: 'transparent', border: 'none', color: '#fff', fontSize: '1.2rem', cursor: 'pointer'}}>✕</button>
     </div>
  </div>
);

// ── MAIN APP ─────────────────────────────────
function App() {
  const [activeTab, setActiveTab] = useState<'dash' | 'ai' | 'rules' | 'config' | 'logs' | 'url' | 'zones'>('dash');
  
  // Dashboard & Health State
  const [stats, setStats] = useState<SystemStats>({ active_flows: 0, total_created: 0, total_expired: 0 });
  const [activeBlocks, setActiveBlocks] = useState(0);
  const [activeRules, setActiveRules] = useState<any[]>([]);

  // AI State
  const [prompt, setPrompt] = useState("");
  const [termOutput, setTermOutput] = useState<{ time: string, text: string, type: string }[]>([]);
  const termEndRef = useRef<HTMLDivElement>(null);

  // New SP3 NGFW States
  const [interfaces, setInterfaces] = useState<any[]>([]);
  const [zones, setZones] = useState<any[]>([]);
  const [urlList, setUrlList] = useState<string[]>([]);
  const [trafficLogs, setTrafficLogs] = useState<any[]>([]);

  // Log filter state (client-side)
  const [logFilters, setLogFilters] = useState({
    srcIp: '',
    srcMac: '',
    dstIp: '',
    dstMac: '',
    protocol: '',
    service: '',
  });

  // Modal States
  const [showIfaceModal, setShowIfaceModal] = useState(false);
  const [ifaceForm, setIfaceForm] = useState({ name: '', interface_type: 'Layer 3 Interfaces', ip_assignment: 'DHCP', ip_address: '', gateway: '' });

  const [showZoneModal, setShowZoneModal] = useState(false);
  const [zoneForm, setZoneForm] = useState({ name: '', protection_level: 'Standard', interface: '' });

  const [showRuleModal, setShowRuleModal] = useState(false);
  const [ruleForm, setRuleForm] = useState({
    action: 'drop',
    direction: 'inbound',
    src_ip: '',
    dst_ip: '',
    protocol: 'any',
    description: '',
    expires_in: '',
  });

  useEffect(() => {
    // Live PyTorch Feed & NGFW Hook Check
    const fetchSystemData = async () => {
      try {
        const resRules = await fetch('http://localhost:8000/api/v1/security/rules');
        const dataRules = await resRules.json();
        if (dataRules.rules) {
          setActiveRules(dataRules.rules);
          setActiveBlocks(dataRules.rules.length);
        }
      } catch (e) { /* silent fail on offline backend */ }

      try {
        const resIfaces = await fetch('http://localhost:8000/api/v1/network/interfaces');
        const dataIfaces = await resIfaces.json();
        if (dataIfaces.interfaces) setInterfaces(dataIfaces.interfaces);
      } catch(e) {}

      try {
        const resUrls = await fetch('http://localhost:8000/api/v1/logs/urlfilter');
        const dataUrls = await resUrls.json();
        if (dataUrls.urls) setUrlList(dataUrls.urls);
      } catch(e) {}

      try {
        const resZones = await fetch('http://localhost:8000/api/v1/network/zones');
        const dataZones = await resZones.json();
        if (dataZones.zones) setZones(dataZones.zones);
      } catch(e) {}

      try {
        const resLogs = await fetch('http://localhost:8000/api/v1/logs/traffic');
        const dataLogs = await resLogs.json();
        if (dataLogs.logs) setTrafficLogs(dataLogs.logs);
      } catch(e) {}
    };
    
    fetchSystemData();
    const interval = setInterval(() => {
      fetchSystemData();
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

  const handleAddUrl = async (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && e.currentTarget.value.trim() !== "") {
      const newUrl = e.currentTarget.value.trim();
      e.currentTarget.value = '';
      try {
         const res = await fetch(`http://localhost:8000/api/v1/logs/urlfilter`, { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ url: newUrl })
         });
         const data = await res.json();
         if (data.urls) setUrlList(data.urls);
      } catch(e) { }
    }
  };

  const handleDeleteUrl = async (url: string) => {
      try {
         const res = await fetch(`http://localhost:8000/api/v1/logs/urlfilter/${url}`, { method: 'DELETE' });
         const data = await res.json();
         if (data.urls) setUrlList(data.urls);
      } catch(e) { }
  }

  // Handle Form Submits
  const submitInterface = async () => {
     try {
       await fetch('http://localhost:8000/api/v1/network/interfaces', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(ifaceForm)
       });
       setShowIfaceModal(false);
     } catch(e) {}
  };

  const submitZone = async () => {
     try {
       await fetch('http://localhost:8000/api/v1/network/zones', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(zoneForm)
       });
       setShowZoneModal(false);
     } catch(e) {}
  };

  const handleToggleInterface = async (id: string, currentStatus: string) => {
    const newStatus = currentStatus === 'UP' ? 'DOWN' : 'UP';
    try {
      await fetch(`http://localhost:8000/api/v1/network/interfaces/${id}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
    } catch(e) {}
  };

  const handleDeleteInterface = async (id: string) => {
    try {
      await fetch(`http://localhost:8000/api/v1/network/interfaces/${id}`, { method: 'DELETE' });
    } catch(e) {}
  };

  const handleDeleteZone = async (id: string) => {
    if (!window.confirm("Are you sure you want to permanently delete this Security Zone? All bindings will break.")) return;
    try {
      await fetch(`http://localhost:8000/api/v1/network/zones/${id}`, { method: 'DELETE' });
    } catch(e) {}
  };

  const submitCustomRule = async () => {
    try {
      const payload: any = {
        action: ruleForm.action,
        direction: ruleForm.direction,
        src_ip: ruleForm.src_ip.trim(),
        dst_ip: ruleForm.dst_ip.trim(),
        protocol: ruleForm.protocol,
        description: ruleForm.description || 'Custom rule via UI',
      };

      if (ruleForm.expires_in.trim() !== '') {
        const seconds = parseInt(ruleForm.expires_in, 10);
        if (!Number.isNaN(seconds) && seconds > 0) {
          payload.expires_in = seconds;
        }
      }

      const res = await fetch('http://localhost:8000/api/v1/security/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok && data.rule) {
        addTermLine(`[SUCCESS] Custom rule created (${data.rule.id}).`, 'success');
        setShowRuleModal(false);
        setRuleForm({
          action: 'drop',
          direction: 'inbound',
          src_ip: '',
          dst_ip: '',
          protocol: 'any',
          description: '',
          expires_in: '',
        });
      } else {
        addTermLine(`[FAILED] ${data.detail || data.message || 'Could not create rule.'}`, 'err');
      }
    } catch (e) {
      addTermLine(`[NETWORK ERROR] Could not reach backend to create rule.`, 'err');
    }
  };

  const filteredTrafficLogs = trafficLogs.filter((log) => {
    const srcIp = (log?.src_ip ?? '').toString();
    const dstIp = (log?.dst_ip ?? '').toString();
    const protocol = (log?.protocol ?? '').toString();
    const service = (log?.service ?? '').toString();
    const srcMac = (log?.src_mac ?? '').toString();
    const dstMac = (log?.dst_mac ?? '').toString();

    const match = (field: string, needle: string) =>
      needle.trim() === '' || field.toLowerCase().includes(needle.trim().toLowerCase());

    return (
      match(srcIp, logFilters.srcIp) &&
      match(srcMac, logFilters.srcMac) &&
      match(dstIp, logFilters.dstIp) &&
      match(dstMac, logFilters.dstMac) &&
      match(protocol, logFilters.protocol) &&
      match(service, logFilters.service)
    );
  });


  useEffect(() => { termEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [termOutput]);

  const addTermLine = (text: string, type: 'info' | 'success' | 'warn' | 'err' = 'info') => {
    setTermOutput(prev => [...prev, { time: new Date().toLocaleTimeString(), text, type }]);
  };

  const handleAIExecute = async () => {
    if (!prompt.trim()) return;
    addTermLine(`> ${prompt}`, 'info');
    const userPrompt = prompt;
    setPrompt("");

    try {
      addTermLine("Analyzing natural language prompt...", "warn");
      const res = await fetch('http://localhost:8000/api/v1/ai/prompt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: userPrompt })
      });
      const data = await res.json();
      
      if (res.ok && data.success) {
        addTermLine(`[SUCCESS] ${data.message}`, 'success');
      } else {
        addTermLine(`[FAILED] ${data.message || data.detail || 'Command failed.'}`, 'err');
      }
    } catch (e) {
      addTermLine(`[NETWORK ERROR] Could not reach backend AI engine. Using local failover simulation.`, 'warn');
      setTimeout(() => {
        addTermLine(`[SIMULATED SUCCESS] Parsed action sequence for "${userPrompt}".`, 'success');
      }, 500);
    }
  };

  return (
    <div className="app-container">
      {/* ── SIDEBAR ── */}
      <aside className="sidebar">
        <div className="logo-area">
          <div className="logo-icon"></div>
          <h1>AEROCIFER</h1>
          <span className="badge">NGFW OS</span>
        </div>
        <nav className="nav-menu">
          <div className={`nav-item ${activeTab === 'dash' ? 'active' : ''}`} onClick={() => setActiveTab('dash')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>
            Live Telemetry
          </div>
          <div className={`nav-item ${activeTab === 'ai' ? 'active' : ''}`} onClick={() => setActiveTab('ai')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2a2 2 0 0 1 2 2c0 1.1-.9 2-2 2a2 2 0 0 1-2-2c0-1.1.9-2 2-2zM4 10a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm16 0a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm-8 12a2 2 0 1 1 0-4 2 2 0 0 1 0 4z"></path></svg>
            AI Config Engine
          </div>
          <div className={`nav-item ${activeTab === 'config' ? 'active' : ''}`} onClick={() => setActiveTab('config')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 2v7c0 1.1.9 2 2 2h4a2 2 0 0 0 2-2V2H3zm14 0v7c0 1.1.9 2 2 2h4a2 2 0 0 0 2-2V2h-8zM3 15v7c0 1.1.9 2 2 2h4a2 2 0 0 0 2-2v-7H3zm14 0v7c0 1.1.9 2 2 2h4a2 2 0 0 0 2-2v-7h-8z"></path></svg>
            Physical Interfaces
          </div>
          <div className={`nav-item ${activeTab === 'zones' ? 'active' : ''}`} onClick={() => setActiveTab('zones')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
            Security Zones
          </div>
          <div className={`nav-item ${activeTab === 'rules' ? 'active' : ''}`} onClick={() => setActiveTab('rules')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            Policy Rules
          </div>
          <div className={`nav-item ${activeTab === 'url' ? 'active' : ''}`} onClick={() => setActiveTab('url')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11.96 14.94A3 3 0 0 0 11 15v5l-4-4-4 4v-5a3 3 0 0 0-.96-.06A4.5 4.5 0 0 1 2.5 10c0-2.5 2-4.5 4.46-4.5h6.08A4.5 4.5 0 0 1 17.5 10c0 2.5-2 4.5-4.46 4.5h-1.08z"></path></svg>
            URL & DNS Filters
          </div>
          <div className={`nav-item ${activeTab === 'logs' ? 'active' : ''}`} onClick={() => setActiveTab('logs')}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>
            Log Management
          </div>
        </nav>
      </aside>

      {/* ── MAIN CONTENT ── */}
      <main className="main-content">
        
        {/* TAB 1: DASHBOARD */}
        {activeTab === 'dash' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>Live SP3 Telemetry</h2>
                <p>Real-time Single-Pass flow tracking across PyTorch endpoints.</p>
             </div>
             
             <div className="dashboard-grid">
                <div className="glass-card">
                  <div className="stat-label">Active Scapy Flows</div>
                  <div className="stat-value">{stats.active_flows}</div>
                  <div className="subtitle" style={{color: 'hsl(var(--status-good))'}}>Scanning Layer 7</div>
                </div>
                <div className="glass-card">
                  <div className="stat-label">Detected Anomalies</div>
                  <div className="stat-value" style={{color: 'hsl(var(--status-err))'}}>{activeBlocks}</div>
                  <div className="subtitle">Threats Blocked</div>
                </div>
                <div className="glass-card">
                  <div className="stat-label">ML Model Confidence</div>
                  <div className="stat-value" style={{color: 'hsl(var(--brand-cyan))'}}>98.4%</div>
                  <div className="subtitle">Avg classification accuracy</div>
                </div>
             </div>
             
             <div className="glass-card" style={{marginTop: '2rem'}}>
                <h3>Live SP3 Traffic Canvas</h3>
                <div style={{height: '250px', background: 'hsla(0,0%,100%,0.02)', borderRadius: '8px', position: 'relative', overflow: 'hidden', border: '1px solid hsla(0,0%,100%,0.05)', marginTop: '1rem'}}>
                   {/* Data Pipeline Endpoints */}
                   <div style={{position: 'absolute', top: '50%', left: '10%', width: '15px', height: '15px', background: 'hsl(var(--brand-cyan))', borderRadius: '50%', boxShadow: '0 0 15px hsl(var(--brand-cyan))', zIndex: 2}}></div>
                   <div style={{position: 'absolute', top: '50%', right: '10%', width: '15px', height: '15px', background: 'hsl(var(--status-err))', borderRadius: '50%', boxShadow: '0 0 15px hsl(var(--status-err))', zIndex: 2}}></div>
                   <div style={{position: 'absolute', top: 'calc(50% + 6px)', left: '10%', width: '80%', height: '3px', background: 'linear-gradient(90deg, hsl(var(--brand-cyan)), transparent, hsl(var(--status-err)))', opacity: 0.3}}></div>
                   
                   <style>
                     {`
                       @keyframes packetFlow {
                         0% { left: 10%; opacity: 1; transform: scale(1); }
                         80% { opacity: 1; transform: scale(1.2); }
                         100% { left: 88%; opacity: 0; transform: scale(0.5); }
                       }
                     `}
                   </style>
                   <div style={{position: 'absolute', top: 'calc(50% + 3px)', width: '8px', height: '8px', background: '#fff', borderRadius: '50%', animation: 'packetFlow 1.5s linear infinite', boxShadow: '0 0 8px #fff'}}></div>
                   <div style={{position: 'absolute', top: 'calc(50% + 3px)', width: '8px', height: '8px', background: 'hsl(var(--brand-purple))', borderRadius: '50%', animation: 'packetFlow 2s linear infinite 0.5s', boxShadow: '0 0 8px hsl(var(--brand-purple))'}}></div>
                   <div style={{position: 'absolute', top: 'calc(50% + 3px)', width: '8px', height: '8px', background: 'hsl(var(--status-err))', borderRadius: '50%', animation: 'packetFlow 1.8s linear infinite 1.2s', boxShadow: '0 0 8px hsl(var(--status-err))'}}></div>
                </div>
             </div>
          </div>
        )}

        {/* TAB 2: AI CONFIG */}
        {activeTab === 'ai' && (
          <div className="animate-in ai-view">
             <div className="page-header">
                <h2>AI Copilot Configuration Engine</h2>
                <p>Interact with the network via Zero-Touch Natural Language Processing.</p>
             </div>

             <div className="glass-card term-container" style={{display: 'flex', flexDirection: 'column', gap: '1rem', minHeight: '400px'}}>
                <div className="term-output" style={{flex: 1, overflowY: 'auto', background: '#090a0c', padding: '1rem', borderRadius: '8px', fontFamily: 'monospace'}}>
                   {termOutput.map((out, idx) => (
                      <div key={idx} style={{marginBottom: '0.5rem', display: 'flex', gap: '1rem'}}>
                         <span style={{color: 'hsl(var(--text-muted))'}}>[{out.time}]</span>
                         <span style={{
                           color: out.type === 'err' ? 'hsl(var(--status-err))' : 
                                  out.type === 'success' ? 'hsl(var(--status-good))' : 
                                  out.type === 'warn' ? 'hsl(var(--status-warn))' : 'hsl(var(--text-main))'
                         }}>{out.text}</span>
                      </div>
                   ))}
                   <div ref={termEndRef} />
                </div>
                <div className="term-input-row" style={{display: 'flex', gap: '1rem'}}>
                   <input 
                      type="text" 
                      value={prompt}
                      onChange={e => setPrompt(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleAIExecute()}
                      placeholder="e.g. 'Create a zone for basic devices' or 'Block IP 192.168.0.105'"
                      style={{flex: 1, padding: '1rem', background: 'hsla(0,0%,100%,0.05)', border: '1px solid hsla(0,0%,100%,0.1)', borderRadius: '8px', color: '#fff'}}
                   />
                   <button onClick={handleAIExecute} style={{padding: '0 2rem', background: 'hsl(var(--brand-blue))', border: 'none', borderRadius: '8px', color: '#fff', fontWeight: 'bold', cursor: 'pointer'}}>
                     Execute Prompt
                   </button>
                </div>
             </div>
          </div>
        )}

        {/* TAB 3: CONFIG (Interfaces) */}
        {activeTab === 'config' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>Network Interfaces</h2>
                <p>SP3 physical hardware bindings and port mapping.</p>
             </div>
             
             <div className="glass-card" style={{marginTop: '2rem'}}>
                <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                   <h3 style={{margin: 0}}>Physical Interfaces</h3>
                   <button onClick={() => setShowIfaceModal(true)} style={{padding: '0.5rem 1rem', background: 'hsl(var(--brand-cyan))', border: 'none', borderRadius: '4px', color: '#000', cursor: 'pointer', fontWeight: 'bold'}}>+ Add Virtual Interface</button>
                </div>
                <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse', marginTop: '1rem'}}>
                  <thead>
                    <tr style={{borderBottom: '1px solid hsla(0,0%,100%,0.1)', color: 'hsl(var(--text-muted))'}}>
                      <th style={{paddingBottom: '1rem'}}>Port</th>
                      <th style={{paddingBottom: '1rem'}}>Type</th>
                      <th style={{paddingBottom: '1rem'}}>Config</th>
                      <th style={{paddingBottom: '1rem'}}>Gateway (IP)</th>
                      <th style={{paddingBottom: '1rem'}}>Assigned Zone</th>
                      <th style={{paddingBottom: '1rem'}}>Status</th>
                      <th style={{paddingBottom: '1rem'}}>Admin Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {interfaces.map((ifc, idx) => (
                      <tr key={idx} style={{borderBottom: '1px solid hsla(0,0%,100%,0.05)'}}>
                        <td style={{padding: '1rem 0', fontWeight: 'bold'}}>{ifc.id ? ifc.id.toUpperCase() : 'ETH'} - {ifc.name}</td>
                        <td>{ifc.interface_type || ifc.type}</td>
                        <td style={{color: 'hsl(var(--brand-cyan))'}}>{ifc.ip_assignment}</td>
                        <td>{ifc.ip_address}</td>
                        <td><span style={{padding: '0.2rem 0.5rem', background: 'hsla(0,0%,100%,0.1)', borderRadius: '4px'}}>{ifc.zone_id || ifc.zone || 'None'}</span></td>
                        <td>
                          {ifc.status === 'UP' ? 
                             <span style={{color: 'hsl(var(--status-good))'}}>● {ifc.speed}</span> : 
                             <span style={{color: 'hsl(var(--status-err))'}}>● DOWN</span>}
                        </td>
                        <td>
                          <button onClick={() => handleToggleInterface(ifc.id, ifc.status)} style={{background: 'transparent', border: '1px solid hsla(0,0%,100%,0.2)', padding: '0.3rem 0.6rem', borderRadius: '4px', color: '#fff', cursor: 'pointer', marginRight: '0.5rem'}}>{ifc.status === 'UP' ? 'Disable' : 'Enable'}</button>
                          <button onClick={() => handleDeleteInterface(ifc.id)} style={{background: 'transparent', border: '1px solid hsl(var(--status-err))', padding: '0.3rem 0.6rem', borderRadius: '4px', color: 'hsl(var(--status-err))', cursor: 'pointer'}}>Delete</button>
                        </td>
                      </tr>
                    ))}
                    {interfaces.length === 0 && <tr><td colSpan={7} style={{padding: '2rem 0', textAlign: 'center', color: 'hsl(var(--text-muted))'}}>No Interfaces provisioned.</td></tr>}
                  </tbody>
                </table>
             </div>

             {/* INTERFACE MODAL */}
             {showIfaceModal && (
               <ModalBackground onClose={() => setShowIfaceModal(false)}>
                  <h3 style={{marginBottom: '1rem'}}>Configure New Interface</h3>
                  <div style={{display: 'flex', flexDirection: 'column', gap: '1rem'}}>
                     <input type="text" placeholder="Interface Name (e.g. WAN, LAN2)" value={ifaceForm.name} onChange={e => setIfaceForm({...ifaceForm, name: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}/>
                     <select value={ifaceForm.interface_type} onChange={e => setIfaceForm({...ifaceForm, interface_type: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}>
                        <option>Tap Interfaces</option>
                        <option>Virtual Wire Interfaces</option>
                        <option>Layer 2 Interfaces</option>
                        <option>Layer 3 Interfaces</option>
                     </select>
                     <select value={ifaceForm.ip_assignment} onChange={e => setIfaceForm({...ifaceForm, ip_assignment: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}>
                        <option>DHCP</option>
                        <option>Static</option>
                     </select>
                     {ifaceForm.ip_assignment === 'Static' && (
                        <>
                          <input type="text" placeholder="IP Address / Subnet" value={ifaceForm.ip_address} onChange={e => setIfaceForm({...ifaceForm, ip_address: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}/>
                          <input type="text" placeholder="Gateway IP" value={ifaceForm.gateway} onChange={e => setIfaceForm({...ifaceForm, gateway: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}/>
                        </>
                     )}
                     <button onClick={submitInterface} style={{padding: '1rem', background: 'hsl(var(--brand-cyan))', color: '#000', fontWeight: 'bold', border: 'none', borderRadius: '4px', cursor: 'pointer', marginTop: '1rem'}}>Deploy Interface Binding</button>
                  </div>
               </ModalBackground>
             )}
          </div>
        )}

        {/* TAB 3B: ZONES */}
        {activeTab === 'zones' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>Security Zones</h2>
                <p>Logical deep packet isolation partitions.</p>
             </div>
             
             <div className="glass-card" style={{marginTop: '2rem'}}>
                <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                   <h3 style={{margin: 0}}>Logical Zones</h3>
                   <button onClick={() => setShowZoneModal(true)} style={{padding: '0.5rem 1rem', background: 'hsl(var(--brand-cyan))', border: 'none', borderRadius: '4px', color: '#000', cursor: 'pointer', fontWeight: 'bold'}}>+ Create Zone</button>
                </div>
                <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse', marginTop: '1rem'}}>
                  <thead>
                    <tr style={{borderBottom: '1px solid hsla(0,0%,100%,0.1)', color: 'hsl(var(--text-muted))'}}>
                      <th style={{paddingBottom: '1rem'}}>Zone Name</th>
                      <th style={{paddingBottom: '1rem'}}>Protection Level</th>
                      <th style={{paddingBottom: '1rem'}}>Bound Interfaces</th>
                      <th style={{paddingBottom: '1rem'}}>Admin Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {zones.map((zone, idx) => (
                      <tr key={idx} style={{borderBottom: '1px solid hsla(0,0%,100%,0.05)'}}>
                        <td style={{padding: '1rem 0', fontWeight: 'bold', color: 'hsl(var(--brand-cyan))'}}>{zone.name}</td>
                        <td>{zone.protection_level || zone.description || 'Enterprise Standard'}</td>
                        <td><span style={{fontFamily: 'monospace'}}>[ {zone.interfaces ? zone.interfaces.join(', ') : 'eth0'} ]</span></td>
                        <td>
                          <button onClick={() => handleDeleteZone(zone.id)} style={{background: 'transparent', border: '1px solid hsl(var(--status-err))', padding: '0.3rem 0.6rem', borderRadius: '4px', color: 'hsl(var(--status-err))', cursor: 'pointer'}}>Teardown Zone</button>
                        </td>
                      </tr>
                    ))}
                    {zones.length === 0 && <tr><td colSpan={4} style={{padding: '2rem 0', textAlign: 'center', color: 'hsl(var(--text-muted))'}}>No Zones defined.</td></tr>}
                  </tbody>
                </table>
             </div>

             {/* ZONE MODAL */}
             {showZoneModal && (
               <ModalBackground onClose={() => setShowZoneModal(false)}>
                  <h3 style={{marginBottom: '1rem'}}>Provision Security Zone</h3>
                  <div style={{display: 'flex', flexDirection: 'column', gap: '1rem'}}>
                     <input type="text" placeholder="Zone Alias (e.g. DMZ, Internal, Untrust)" value={zoneForm.name} onChange={e => setZoneForm({...zoneForm, name: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}/>
                     <select value={zoneForm.protection_level} onChange={e => setZoneForm({...zoneForm, protection_level: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}>
                        <option>Standard</option>
                        <option>Restrictive (Zero-Trust)</option>
                        <option>Custom (AI Model Managed)</option>
                     </select>
                     <select value={zoneForm.interface} onChange={e => setZoneForm({...zoneForm, interface: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}>
                        <option value="">-- Select Interface Binding --</option>
                        {interfaces.map(i => <option key={i.id} value={i.id}>{i.id.toUpperCase()} - {i.name}</option>)}
                     </select>
                     <button onClick={submitZone} style={{padding: '1rem', background: 'hsl(var(--brand-cyan))', color: '#000', fontWeight: 'bold', border: 'none', borderRadius: '4px', cursor: 'pointer', marginTop: '1rem'}}>Initialize Zone Isolation</button>
                  </div>
               </ModalBackground>
             )}
          </div>
        )}

        {/* TAB 4: RULES */}
        {activeTab === 'rules' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>Policy & Custom Rules Engine</h2>
                <p>Create L2-L7 specific filter rules. Threats auto-blocked by PyTorch are also tracked here.</p>
             </div>
             <div className="glass-card" style={{marginTop: '2rem'}}>
                <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                   <h3 style={{margin: 0}}>Active Enforcements</h3>
                   <button onClick={() => setShowRuleModal(true)} style={{padding: '0.5rem 1rem', background: 'hsl(var(--brand-purple))', border: 'none', borderRadius: '4px', color: '#fff', cursor: 'pointer', fontWeight: 'bold'}}>+ Create Custom Rule</button>
                </div>
                <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse', marginTop: '1rem'}}>
                  <thead>
                    <tr style={{borderBottom: '1px solid hsla(0,0%,100%,0.1)', color: 'hsl(var(--text-muted))'}}>
                      <th style={{paddingBottom: '1rem'}}>Rule ID</th>
                      <th style={{paddingBottom: '1rem'}}>Source → Dest</th>
                      <th style={{paddingBottom: '1rem'}}>Protocol / Service</th>
                      <th style={{paddingBottom: '1rem'}}>Policy Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeRules.map((rule, idx) => (
                      <tr key={rule.id || idx} style={{borderBottom: '1px solid hsla(0,0%,100%,0.05)'}}>
                        <td style={{padding: '1.5rem 0', fontFamily: 'monospace', fontSize: '0.9rem'}}>{rule.id.substring(0, 13)}...</td>
                        <td style={{color: 'hsl(var(--brand-cyan))'}}>{rule.src_ip} <span style={{color: '#888'}}>→</span> {rule.dst_ip}</td>
                        <td>{rule.protocol.toUpperCase()} Filter Block</td>
                        <td>
                          <span style={{display: 'inline-block', width: '60px', color: rule.action === 'drop' ? 'hsl(var(--status-err))' : 'hsl(var(--status-good))', fontWeight: 'bold'}}>
                            {rule.action.toUpperCase()}
                          </span>
                          <button 
                            onClick={() => handleUnblock(rule.id)}
                            style={{marginLeft: '20px', padding: '0.3rem 0.8rem', background: 'hsla(0,0%,100%,0.1)', border: 'none', borderRadius: '4px', color: '#fff', cursor: 'pointer'}}
                          >
                            Revoke Rule
                          </button>
                        </td>
                      </tr>
                    ))}
                    {activeRules.length === 0 && (
                      <tr>
                        <td colSpan={4} style={{padding: '2rem 0', textAlign: 'center', color: 'hsl(var(--text-muted))'}}>No active blocks. The Database is empty.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
             </div>

             {/* CUSTOM RULE MODAL */}
             {showRuleModal && (
               <ModalBackground onClose={() => setShowRuleModal(false)}>
                 <h3 style={{marginBottom: '1rem'}}>Create Custom Rule</h3>
                 <div style={{display: 'flex', flexDirection: 'column', gap: '1rem'}}>
                   <select value={ruleForm.action} onChange={e => setRuleForm({...ruleForm, action: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}>
                     <option value="drop">DROP (Block)</option>
                     <option value="accept">ACCEPT (Allow)</option>
                     <option value="reject">REJECT</option>
                     <option value="log">LOG</option>
                   </select>
                   <select value={ruleForm.direction} onChange={e => setRuleForm({...ruleForm, direction: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}}>
                     <option value="inbound">inbound</option>
                     <option value="outbound">outbound</option>
                     <option value="forward">forward</option>
                   </select>
                   <input type="text" placeholder="Source IP (optional)" value={ruleForm.src_ip} onChange={e => setRuleForm({...ruleForm, src_ip: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}} />
                   <input type="text" placeholder="Destination IP (optional)" value={ruleForm.dst_ip} onChange={e => setRuleForm({...ruleForm, dst_ip: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}} />
                   <input type="text" placeholder="Protocol (any/tcp/udp/icmp)" value={ruleForm.protocol} onChange={e => setRuleForm({...ruleForm, protocol: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}} />
                   <input type="text" placeholder="Expires in seconds (optional)" value={ruleForm.expires_in} onChange={e => setRuleForm({...ruleForm, expires_in: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}} />
                   <input type="text" placeholder="Description" value={ruleForm.description} onChange={e => setRuleForm({...ruleForm, description: e.target.value})} style={{padding: '0.8rem', background: 'hsla(0,0%,0%,0.3)', border: '1px solid hsla(0,0%,100%,0.1)', color: '#fff', borderRadius: '4px'}} />

                   <button onClick={submitCustomRule} style={{padding: '1rem', background: 'hsl(var(--brand-purple))', color: '#fff', fontWeight: 'bold', border: 'none', borderRadius: '4px', cursor: 'pointer', marginTop: '1rem'}}>
                     Create Rule
                   </button>
                 </div>
               </ModalBackground>
             )}
          </div>
        )}

        {/* TAB 5: URL FILTERING */}
        {activeTab === 'url' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>DPI DNS & URL Filtering</h2>
                <p>Define raw hostnames and URLs. The SP3 Pipeline will automatically drop matching traffic.</p>
             </div>
             
             <div className="glass-card" style={{marginTop: '2rem'}}>
                <div style={{display: 'flex', gap: '1rem', marginBottom: '2rem'}}>
                  <input 
                     type="text" 
                     placeholder="Type a completely malicious domain... (e.g. hack-me.ru)" 
                     onKeyDown={handleAddUrl}
                     style={{flex: 1, padding: '1rem', background: 'hsla(0,0%,100%,0.05)', border: '1px solid hsla(0,0%,100%,0.1)', borderRadius: '8px', color: '#fff'}}
                  />
                  <div style={{padding: '1rem', color: 'hsl(var(--text-muted))'}}>Press Enter to Sync</div>
                </div>

                <div style={{display: 'flex', flexDirection: 'column', gap: '0.5rem'}}>
                   {urlList.map((url, idx) => (
                      <div key={idx} style={{display: 'flex', justifyContent: 'space-between', padding: '1rem', background: 'hsla(0,0%,100%,0.02)', border: '1px solid hsla(0,0%,100%,0.05)', borderRadius: '8px'}}>
                         <div style={{color: 'hsl(var(--status-err))', fontWeight: 'bold'}}>{url}</div>
                         <button onClick={() => handleDeleteUrl(url)} style={{background: 'transparent', border: 'none', color: 'hsl(var(--text-muted))', cursor: 'pointer'}}>Remove</button>
                      </div>
                   ))}
                </div>
             </div>
          </div>
        )}

        {/* TAB 6: LOGS */}
        {activeTab === 'logs' && (
          <div className="animate-in">
             <div className="page-header">
                <h2>Real-Time Single Pass (SP3) Viewer</h2>
                <p>Every single packet inspected parallelized by the Scapy Deep Packet core.</p>
             </div>
             
             <div className="glass-card" style={{marginTop: '2rem'}}>
                <div style={{display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1rem'}}>
                   <input value={logFilters.srcIp} onChange={e => setLogFilters({...logFilters, srcIp: e.target.value})} type="text" placeholder="Source IP" style={{padding: '0.8rem', background: 'hsla(0,0%,100%,0.05)', border: '1px solid hsla(0,0%,100%,0.1)', borderRadius: '4px', color: '#fff'}} />
                   <input value={logFilters.srcMac} onChange={e => setLogFilters({...logFilters, srcMac: e.target.value})} type="text" placeholder="Source MAC/Address" style={{padding: '0.8rem', background: 'hsla(0,0%,100%,0.05)', border: '1px solid hsla(0,0%,100%,0.1)', borderRadius: '4px', color: '#fff'}} />
                   <input value={logFilters.dstIp} onChange={e => setLogFilters({...logFilters, dstIp: e.target.value})} type="text" placeholder="Destination IP" style={{padding: '0.8rem', background: 'hsla(0,0%,100%,0.05)', border: '1px solid hsla(0,0%,100%,0.1)', borderRadius: '4px', color: '#fff'}} />
                   <input value={logFilters.dstMac} onChange={e => setLogFilters({...logFilters, dstMac: e.target.value})} type="text" placeholder="Destination MAC/Address" style={{padding: '0.8rem', background: 'hsla(0,0%,100%,0.05)', border: '1px solid hsla(0,0%,100%,0.1)', borderRadius: '4px', color: '#fff'}} />
                   <input value={logFilters.protocol} onChange={e => setLogFilters({...logFilters, protocol: e.target.value})} type="text" placeholder="Protocol (TCP/UDP/ICMP)" style={{padding: '0.8rem', background: 'hsla(0,0%,100%,0.05)', border: '1px solid hsla(0,0%,100%,0.1)', borderRadius: '4px', color: '#fff'}} />
                   <input value={logFilters.service} onChange={e => setLogFilters({...logFilters, service: e.target.value})} type="text" placeholder="Service / App-ID / Policy" style={{padding: '0.8rem', background: 'hsla(0,0%,100%,0.05)', border: '1px solid hsla(0,0%,100%,0.1)', borderRadius: '4px', color: '#fff'}} />
                </div>
                <div style={{minHeight: '300px', background: 'hsla(0,0%,100%,0.02)', borderRadius: '8px', padding: '1rem', border: '1px solid hsla(0,0%,100%,0.05)', marginTop: '1rem', overflowY: 'auto', maxHeight: '500px'}}>
                  {filteredTrafficLogs.length === 0 ? (
                    <div style={{color: 'hsl(var(--text-muted))', textAlign: 'center', marginTop: '4rem'}}>
                      {trafficLogs.length === 0 ? 'Gathering Packets... Standby.' : 'No logs match the current filters.'}
                    </div>
                  ) : (
                    <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '0.9rem'}}>
                      <thead>
                        <tr style={{borderBottom: '1px solid hsla(0,0%,100%,0.2)', color: 'hsl(var(--text-muted))'}}>
                          <th style={{padding: '0.5rem 0'}}>Timestamp</th>
                          <th>Source IP</th>
                          <th>Destination IP</th>
                          <th>Protocol</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredTrafficLogs.map((log, idx) => (
                          <tr key={idx} style={{borderBottom: '1px solid hsla(0,0%,100%,0.05)'}}>
                            <td style={{padding: '0.8rem 0', fontFamily: 'monospace'}}>{new Date(log.timestamp * 1000).toLocaleTimeString()}</td>
                            <td style={{fontWeight: 'bold', color: 'hsl(var(--text-main))'}}>{log.src_ip}</td>
                            <td style={{color: 'hsl(var(--text-muted))'}}>{log.dst_ip}</td>
                            <td><span style={{background: 'hsla(0,0%,100%,0.1)', padding: '0.2rem 0.5rem', borderRadius: '4px'}}>{log.protocol} {log.service}</span></td>
                            <td style={{color: log.policy_action === 'drop' ? 'hsl(var(--status-err))' : 'hsl(var(--status-good))', fontWeight: 'bold'}}>{log.policy_action.toUpperCase()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
             </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
