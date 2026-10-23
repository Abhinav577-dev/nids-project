
import { useState, useEffect } from "react";
import { api, DEMO_MODE } from "./services/api";
import {
  Activity, Shield, ShieldAlert, LayoutDashboard, Network,
  Bell, Database, Settings, Search, Download, ArrowUpRight,
  CircleCheck, Radio, Wifi, Server, Menu, ChevronDown
} from "lucide-react";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  Tooltip, CartesianGrid, PieChart, Pie, Cell
} from "recharts";
import "./App.css";

const traffic = [
  { time: "09:00", flows: 120, threats: 12 },
  { time: "10:00", flows: 185, threats: 18 },
  { time: "11:00", flows: 240, threats: 25 },
  { time: "12:00", flows: 310, threats: 31 },
  { time: "13:00", flows: 290, threats: 19 },
  { time: "14:00", flows: 460, threats: 48 },
];

const protocols = [
  { name: "TCP", value: 58, color: "#38bdf8" },
  { name: "UDP", value: 27, color: "#818cf8" },
  { name: "Other", value: 15, color: "#34d399" },
];

const flows = [
  { id: "FL-1082", src: "192.168.1.14", dst: "185.199.110.153", port: 443, protocol: "TCP", type: "Benign", time: "14:32:18" },
  { id: "FL-1081", src: "192.168.1.22", dst: "45.33.32.156", port: 22, protocol: "TCP", type: "Potential threat", time: "14:31:52" },
  { id: "FL-1080", src: "192.168.1.14", dst: "142.250.183.14", port: 443, protocol: "TCP", type: "Benign", time: "14:30:41" },
  { id: "FL-1079", src: "192.168.1.19", dst: "103.21.244.0", port: 80, protocol: "TCP", type: "Potential threat", time: "14:29:06" },
  { id: "FL-1078", src: "192.168.1.22", dst: "8.8.8.8", port: 53, protocol: "UDP", type: "Benign", time: "14:28:33" },
];

const pages = [
  ["Overview", LayoutDashboard],
  ["Threat Center", ShieldAlert],
  ["Network Analytics", Activity],
  ["Alerts", Bell],
  ["Data Explorer", Database],
];

function App() {
  const [page, setPage] = useState("Overview");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [selected, setSelected] = useState(null);

  const [apiStatus, setApiStatus] = useState("checking");
  const [overview, setOverview] = useState(null);
const [overviewError, setOverviewError] = useState(false);

const [flowRecords, setFlowRecords] = useState([]);
const [flowsError, setFlowsError] = useState(false);
const [alertRecords, setAlertRecords] = useState([]);
const [alertsError, setAlertsError] = useState(false);
const [analytics, setAnalytics] = useState(null);
const [analyticsError, setAnalyticsError] = useState(false);
const [pipeline, setPipeline] = useState(null);
const [pipelineError, setPipelineError] = useState(false);
const [backendMode, setBackendMode] = useState("checking");

useEffect(() => {
  let active = true;

  // 1. Check backend health
  api.health()
    // 1. Check backend health and detection pipeline
api.health()
  .then((data) => {
    if (active) {
      setApiStatus(
        data.status === "healthy" ? "connected" : "unavailable"
      );

      setBackendMode(
        data.detection_pipeline === "connected"
          ? "live"
          : data.detection_pipeline === "data_sources_configured"
            ? "configured"
            : "demo"
      );
    }
  })
  .catch(() => {
    if (active) {
      setApiStatus("unavailable");
      setBackendMode("unavailable");
    }
  });

  // 2. Fetch overview metrics
  api.overview()
    .then((data) => {
      if (active) {
        setOverview(data);
        setOverviewError(false);
      }
    })
    .catch(() => {
      if (active) {
        setOverviewError(true);
        setOverview(null);
      }
    });

  // 3. Fetch flow records
  api.flows()
    .then((data) => {
      if (active) {
        setFlowRecords(data.flows ?? []);
        setFlowsError(false);
      }
    })
    .catch(() => {
      if (active) {
        setFlowRecords([]);
        setFlowsError(true);
      }
    });

  // 4. Fetch alerts
  api.alerts()
    .then((data) => {
      if (active) {
        setAlertRecords(data.alerts ?? []);
        setAlertsError(false);
      }
    })
    .catch(() => {
      if (active) {
        setAlertRecords([]);
        setAlertsError(true);
      }
    });

  // 5. Fetch analytics
  api.analytics()
    .then((data) => {
      if (active) {
        setAnalytics(data);
        setAnalyticsError(false);
      }
    })
    .catch(() => {
      if (active) {
        setAnalytics(null);
        setAnalyticsError(true);
      }
    });

  // 6. Fetch pipeline health
  api.pipeline()
    .then((data) => {
      if (active) {
        setPipeline(data);
        setPipelineError(false);
      }
    })
    .catch(() => {
      if (active) {
        setPipeline(null);
        setPipelineError(true);
      }
    });

  return () => {
    active = false;
  };
}, []);

  const visibleFlows = flowRecords.filter((f) => {
    const matches = Object.values(f).some((v) =>
      String(v).toLowerCase().includes(search.toLowerCase())
    );
    return matches && (filter === "All" || f.type === filter);
  });

  function exportCSV() {
    const rows = [
      ["Flow ID", "Source", "Destination", "Port", "Protocol", "Classification", "Time"],
      ...visibleFlows.map(f => [f.id, f.src, f.dst, f.port, f.protocol, f.type, f.time]),
    ];
    const csv = rows.map(row => row.join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "sentinel-demo-flows.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Shield size={24} /></div>
          <div><h2>SENTINEL<span>.</span></h2><small>NETWORK DEFENSE CENTER</small></div>
        </div>

        <div className="nav-caption">WORKSPACE</div>
        {pages.map(([label, Icon]) => (
          <button key={label} className={`nav-item ${page === label ? "active" : ""}`}
            onClick={() => setPage(label)}>
            <Icon size={18} /> {label}
            {label === "Alerts" && <span className="nav-count">2</span>}
          </button>
        ))}

        <div className="nav-caption system-caption">SYSTEM</div>
        <button className={`nav-item ${page === "Pipeline Health" ? "active" : ""}`}
          onClick={() => setPage("Pipeline Health")}><Server size={18} /> Pipeline Health</button>
        <button className={`nav-item ${page === "Settings" ? "active" : ""}`}
          onClick={() => setPage("Settings")}><Settings size={18} /> Settings</button>

        <div className="sidebar-bottom">
          <div className="environment"><span /> <div><b>DEMO ENVIRONMENT</b><small>Local preview mode</small></div></div>
          <div className="profile"><div className="avatar">SA</div><div><b>Security Analyst</b><small>Project workspace</small></div></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">Workspace <span>/</span> {page}</div>
          <div className="top-actions">
            <span className="demo-pill">
  <i />
  {backendMode === "checking"
    ? "CHECKING API"
    : backendMode === "unavailable"
      ? "API UNAVAILABLE"
      : backendMode === "live"
        ? "LIVE DATA MODE"
        : backendMode === "configured"
          ? "DATA SOURCE CONFIGURED"
          : "DEMO MODE"}
</span>

<span className="status-tag">
  {apiStatus === "checking" && "CHECKING API"}
  {apiStatus === "connected" && "API CONNECTED"}
  {apiStatus === "unavailable" && "BACKEND UNAVAILABLE"}
</span>
            <button className="icon-button" onClick={() => setPage("Alerts")} aria-label="Alerts"><Bell size={19} /></button>
            <div className="avatar">SA</div>
          </div>
        </header>

        <div className="content">
          <div className="demo-banner"><Radio size={17} /><span><b>DEMO MODE</b> Sample data only. These are not live network detections.</span><small>SIMULATED DATA</small></div>

          <div className="heading">
            <div><div className="eyebrow">SECURITY OPERATIONS</div><h1>{page}</h1><p>Monitor network activity, review model classifications, and investigate potential threats.</p></div>
            <button className="outline-button" onClick={() => { setSearch(""); setFilter("All"); }}>Reset filters</button>
          </div>

          {page === "Overview" && <>
  {overviewError && (
    <p role="alert">
      Unable to load overview data from the backend.
      Please check the API server.
    </p>
  )}

  <section className="metrics">
    <Metric
      title="Captured Flows"
      value={overview ? overview.captured_flows.toLocaleString() : "—"}
      note="API-reported demo records"
      icon={Network}
      color="cyan"
    />
    <Metric
      title="Benign Flows"
      value={overview ? overview.benign_flows.toLocaleString() : "—"}
      note="API-reported demo records"
      icon={CircleCheck}
      color="green"
    />
    <Metric
      title="Potential Threats"
      value={overview ? overview.potential_threats.toLocaleString() : "—"}
      note="Demo classifications"
      icon={ShieldAlert}
      color="red"
    />
    <Metric
      title="Recorded Alerts"
      value={overview ? overview.recorded_alerts.toLocaleString() : "—"}
      note="Simulated alert records"
      icon={Bell}
      color="purple"
    />
  </section>

  <section className="charts">
    <article className="panel">
      <div className="panel-heading">
        <div>
          <h3>Network Activity</h3>
          <p>Illustrative traffic volume over time</p>
        </div>
        <span className="mini-pill">
          SAMPLE <ChevronDown size={13} />
        </span>
      </div>

      <div className="legend">
        <span><i className="cyan-dot" /> Total flows</span>
        <span><i className="purple-dot" /> Potential threats</span>
      </div>

      <div className="traffic-chart">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={analytics?.traffic ?? []}>
            <defs>
              <linearGradient id="flowFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#202c40" strokeDasharray="3 5" vertical={false} />
            <XAxis dataKey="time" tick={{ fill: "#8292a9", fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: "#8292a9", fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: "#111c2d", border: "1px solid #29364b", borderRadius: 8 }} />
            <Area dataKey="flows" name="Total flows" stroke="#38bdf8" fill="url(#flowFill)" strokeWidth={2.5} />
            <Area dataKey="threats" name="Potential threats" stroke="#818cf8" fill="transparent" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-footer">
        <span><i /> Example activity timeline</span>
        <span>Not live traffic</span>
      </div>
    </article>

    <article className="panel protocol-panel">
      <div className="panel-heading">
        <div>
          <h3>Protocol Distribution</h3>
          <p>Sample traffic composition</p>
        </div>
      </div>

      <div className="donut">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={analytics?.protocols ?? []}
              dataKey="value"
              nameKey="name"
              innerRadius={61}
              outerRadius={83}
              paddingAngle={4}
              stroke="none"
            >
              {protocols.map(p => (
                <Cell key={p.name} fill={p.color} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-label">
          <b>100%</b>
          <small>Sample data</small>
        </div>
      </div>

      <div className="protocol-legend">
        {protocols.map(p => (
          <div key={p.name}>
            <span>
              <i style={{ background: p.color }} />
              {p.name}
            </span>
            <b>{p.value}%</b>
          </div>
        ))}
      </div>
    </article>
  </section>

  <section className="panel table-panel">
    <div className="panel-heading">
      <div>
        <h3>Recent Flow Records</h3>
        <p>Example records for testing the interface</p>
      </div>
      <button
        className="outline-button"
        onClick={() => setPage("Threat Center")}
      >
        View all <ArrowUpRight size={15} />
      </button>
    </div>
    <FlowTable rows={flowRecords.slice(0, 4)} onSelect={setSelected} />
  </section>

  <section className="bottom-grid">
    <article className="panel">
      <div className="panel-heading">
        <div>
          <h3>Detection Pipeline</h3>
          <p>Integration readiness</p>
        </div>
        <span className="status-tag">NOT CONNECTED</span>
      </div>
      {pipeline?.components?.map((component) => {
  const statusMap = {
    connected: "connected",
    healthy: "connected",
    unavailable: "unavailable",
    not_connected: "pending",
  };

  const iconMap = {
    "Network Capture": Wifi,
    CICFlowMeter: Activity,
    "ML Detection Model": Activity,
    "Alert Engine": Database,
  };

  const detailMap = {
    "Network Capture": "Network traffic capture",
    CICFlowMeter: "Flow generation engine",
    "ML Detection Model": "Random Forest inference",
    "Alert Engine": "Threat alert processing",
  };

  return (
    <Pipeline
      key={component.name}
      icon={iconMap[component.name] || Server}
      title={component.name}
      detail={detailMap[component.name] || "Pipeline component"}
      status={
        pipelineError
          ? "unavailable"
          : statusMap[component.status] || "pending"
      }
    />
  );
})}
    </article>

    <article className="panel info-panel">
      <div className="info-icon"><Shield size={22} /></div>
      <h3>Detection, with transparency.</h3>
      <p>
        SENTINEL demonstrates machine-learning-based network flow
        classification. A model-classified threat is a signal to
        investigate, not proof of a confirmed intrusion.
      </p>
      <div className="info-footer">Built for network visibility</div>
    </article>
  </section>
</>}

          {page === "Threat Center" && <section className="panel table-panel"><div className="panel-heading"><div><h3>Flow Investigation</h3><p>Search and inspect illustrative flow records.</p></div><button className="outline-button" onClick={exportCSV}><Download size={15} /> Export CSV</button></div><FlowControls search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} /><FlowTable rows={visibleFlows} onSelect={setSelected} /></section>}

          {page === "Network Analytics" && <section className="panel"><div className="panel-heading"><div><h3>Traffic Trends</h3><p>Illustrative flow counts</p></div></div><div className="traffic-chart large-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={traffic}><CartesianGrid stroke="#202c40" strokeDasharray="3 5" /><XAxis dataKey="time" tick={{ fill: "#8292a9" }} /><YAxis tick={{ fill: "#8292a9" }} /><Tooltip /><Area dataKey="flows" stroke="#38bdf8" fill="#38bdf8" fillOpacity={0.12} /></AreaChart></ResponsiveContainer></div></section>}

          {page === "Alerts" && <section className="panel table-panel"><div className="panel-heading"><div><h3>Alert Records</h3><p>Illustrative classifications, not real incidents.</p></div><span className="status-tag">DEMO RECORDS</span></div>{alertRecords.filter(f => f.type === "Potential threat").map(f => <button className="alert-row" key={f.id} onClick={() => setSelected(f)}><ShieldAlert size={19} /><span><b>Potential threat classification</b><small>{f.src} → {f.dst} · Port {f.port} · {f.time}</small></span><ArrowUpRight size={16} /></button>)}</section>}

          {page === "Data Explorer" && <section className="panel table-panel"><div className="panel-heading"><div><h3>Data Explorer</h3><p>Inspect and export sample flow records.</p></div><button className="outline-button" onClick={exportCSV}><Download size={15} /> Export CSV</button></div><FlowControls search={search} setSearch={setSearch} filter={filter} setFilter={setFilter} /><FlowTable rows={visibleFlows} onSelect={setSelected} /></section>}

          {page === "Pipeline Health" && (
  <section className="panel table-panel">
    <div className="panel-heading">
      <div>
        <h3>Pipeline Health</h3>
        <p>Current frontend integration status</p>
      </div>

      <span className="status-tag">
        {pipelineError
          ? "API UNAVAILABLE"
          : !pipeline
          ? "CHECKING"
          : "DEMO MODE"}
      </span>
    </div>

    {pipelineError && (
      <p role="alert">
        Unable to load pipeline status from the backend.
      </p>
    )}

    {!pipelineError && !pipeline && (
      <p>Loading pipeline status...</p>
    )}

    {pipeline?.components?.map((component) => {
      const iconMap = {
        "Network Capture": Wifi,
        CICFlowMeter: Activity,
        "ML Detection Model": Activity,
        "Alert Engine": Database,
      };

      const detailMap = {
        "Network Capture": "Network traffic capture",
        CICFlowMeter: "Flow generation engine",
        "ML Detection Model": "Random Forest inference",
        "Alert Engine": "Threat alert processing",
      };

      return (
        <Pipeline
          key={component.name}
          icon={iconMap[component.name] || Server}
          title={component.name}
          detail={detailMap[component.name] || "Pipeline component"}
          status={
            component.status === "connected" ||
            component.status === "healthy"
              ? "connected"
              : component.status === "unavailable"
              ? "unavailable"
              : "pending"
          }
        />
      );
    })}
  </section>
)}
          {page === "Settings" && <section className="panel table-panel"><h3>Workspace Settings</h3><p>Data source: sample dataset. Backend URL: not configured.</p><p>We'll configure live API integration after inspecting your Ubuntu project.</p></section>}

          <footer className="footer"><span>SENTINEL / Network Defense Center</span><span>Demo environment · No live detections</span></footer>
        </div>
      </main>

      {selected && <div className="modal-backdrop" onClick={() => setSelected(null)}><section className="modal" onClick={e => e.stopPropagation()}><div className="panel-heading"><div><small>FLOW INVESTIGATION</small><h3>{selected.id}</h3></div><button className="icon-button" onClick={() => setSelected(null)}>✕</button></div><p className="modal-note">Illustrative demo record, not a live network event.</p><div className="details">{[["Classification", selected.type], ["Protocol", selected.protocol], ["Source IP", selected.src], ["Destination IP", selected.dst], ["Destination port", selected.port], ["Timestamp", selected.time]].map(([k,v]) => <div key={k}><small>{k}</small><b>{v}</b></div>)}</div><button className="primary-button" onClick={() => setSelected(null)}>Close investigation</button></section></div>}
    </div>
  );
}

function Metric({ title, value, note, icon: Icon, color }) {
  return <article className="metric-card"><div className="metric-top"><span>{title}</span><div className={`metric-icon ${color}`}><Icon size={19} /></div></div><strong>{value}</strong><small>{note}</small></article>;
}

function FlowControls({ search, setSearch, filter, setFilter }) {
  return <div className="flow-controls"><div className="search-box"><Search size={17} /><input placeholder="Search IP, protocol, classification..." value={search} onChange={e => setSearch(e.target.value)} /></div><select value={filter} onChange={e => setFilter(e.target.value)}><option>All</option><option>Benign</option><option>Potential threat</option></select></div>;
}

function FlowTable({ rows, onSelect }) {
  return <div className="table-scroll"><table className="flow-table"><thead><tr><th>FLOW ID</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>CLASSIFICATION</th><th>TIME</th></tr></thead><tbody>{rows.map(f => <tr key={f.id} onClick={() => onSelect(f)}><td className="flow-id">{f.id}</td><td>{f.src}</td><td>{f.dst}<small>Port {f.port}</small></td><td><span className="protocol-badge">{f.protocol}</span></td><td><span className={`classification ${f.type === "Benign" ? "benign" : "threat"}`}>{f.type}</span></td><td>{f.time}</td></tr>)}</tbody></table>{rows.length === 0 && <p className="empty">No matching records. Try another filter.</p>}</div>;
}

function Pipeline({ icon: Icon, title, detail, status }) {
  const isConnected = status === "connected";
  const isUnavailable = status === "unavailable";

  return (
    <div className="pipeline-row">
      <div className="pipeline-icon">
        <Icon size={17} />
      </div>

      <div>
        <b>{title}</b>
        <small>{detail}</small>
      </div>

      <span
        className={
          isConnected
            ? "connected"
            : isUnavailable
            ? "unavailable"
            : "pending"
        }
      >
        {isConnected
          ? "Connected"
          : isUnavailable
          ? "Unavailable"
          : "Not connected"}
      </span>
    </div>
  );
}

export default App;
