import { useState, useRef, useEffect, useCallback } from "react";

/* ------------------------------------------------------------------
   CONFIG
   Relative path, so the same build works in both places:
   - locally, Vite's dev proxy forwards /api to Flask on port 8080
   - on Vercel, vercel.json routes /api/* to api/index.py
------------------------------------------------------------------- */
const API_URL = "/api/analyze";
const QUERY_PARAM = "query"; // calls /api/analyze?query=google.com

/* ---------------------------- helpers ---------------------------- */
const IPV4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;
const DOMAIN =
  /^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$/;

function detectType(value) {
  const v = value.trim();
  if (!v) return null;
  if (IPV4.test(v) || IPV6.test(v)) return "IP Address";
  if (DOMAIN.test(v)) return "Domain Name";
  return "invalid";
}

function countryName(code) {
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(code) || code;
  } catch {
    return code || "Unknown";
  }
}

/* One 0-100 risk score from both sources.
   Each VirusTotal detection adds 15 points (5+ engines = high risk),
   and the result is whichever is worse: that or the AbuseIPDB score. */
function assessThreat(data) {
  const mal = data?.virustotal?.malicious_flags ?? 0;
  const conf = data?.abuseipdb?.confidence_score ?? 0;
  const vtScore = Math.min(100, mal * 15);
  const score = Math.round(Math.max(vtScore, conf));
  if (score >= 75) return { level: "critical", label: "High Risk", score };
  if (score > 0) return { level: "warning", label: "Suspicious", score };
  return { level: "good", label: "Clean", score };
}

function levelFor(value, high = 75) {
  if (value >= high) return "critical";
  if (value > 0) return "warning";
  return "good";
}

const timeUTC = (d) =>
  d.toISOString().slice(11, 19) + " UTC";

/* ------------------------------ icons ---------------------------- */
function StatusIcon({ level, size = 16 }) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    strokeWidth: 2.2,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": true,
  };
  if (level === "critical")
    return (
      <svg {...common} className="sc-ico sc-ico--critical">
        <path d="M8.2 2h7.6L22 8.2v7.6L15.8 22H8.2L2 15.8V8.2z" />
        <path d="M15 9l-6 6M9 9l6 6" />
      </svg>
    );
  if (level === "warning")
    return (
      <svg {...common} className="sc-ico sc-ico--warning">
        <path d="M12 3 2 21h20L12 3z" />
        <path d="M12 10v4M12 17.5v.01" />
      </svg>
    );
  if (level === "good")
    return (
      <svg {...common} className="sc-ico sc-ico--good">
        <circle cx="12" cy="12" r="10" />
        <path d="m7.5 12.5 3 3 6-6.5" />
      </svg>
    );
  return (
    <svg {...common} className="sc-ico sc-ico--info">
      <circle cx="12" cy="12" r="10" />
      <path d="M12 11v6M12 7.5v.01" />
    </svg>
  );
}

function StatusChip({ level, children }) {
  return (
    <span className={`sc-chip sc-chip--${level}`}>
      <StatusIcon level={level} size={14} />
      {children}
    </span>
  );
}

function Flag({ code }) {
  const [failed, setFailed] = useState(false);
  if (!code || code.length !== 2 || failed)
    return <span className="sc-flag sc-flag--text">{code || "??"}</span>;
  return (
    <img
      className="sc-flag"
      src={`https://flagcdn.com/w40/${code.toLowerCase()}.png`}
      alt=""
      width="28"
      height="20"
      onError={() => setFailed(true)}
    />
  );
}

/* ----------------------------- top bar --------------------------- */
function TopBar() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <header className="sc-topbar sc-glass">
      <div className="sc-brand">
        <span className="sc-brand__mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </span>
        <div>
          <span className="sc-brand__name">CTI Console</span>
          <span className="sc-brand__sub">Threat Intelligence Operations</span>
        </div>
      </div>
      <div className="sc-topbar__meta">
        <span className="sc-sources">
          <span className="sc-live" /> VirusTotal · AbuseIPDB
        </span>
        <span className="sc-clock sc-mono">{timeUTC(now)}</span>
      </div>
    </header>
  );
}

/* --------------------------- command bar ------------------------- */
function CommandBar({ onSearch, loading }) {
  const [value, setValue] = useState("");
  const inputRef = useRef(null);
  const type = detectType(value);
  const valid = type && type !== "invalid";

  useEffect(() => {
    inputRef.current?.focus();
    const onKey = (e) => {
      if (e.key === "/" && document.activeElement !== inputRef.current) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const run = (q) => {
    setValue(q);
    onSearch(q);
  };

  const submit = (e) => {
    e.preventDefault();
    if (valid && !loading) onSearch(value.trim());
  };

  return (
    <section className="sc-command">
      <form onSubmit={submit} className={`sc-search sc-glass ${type === "invalid" ? "is-invalid" : ""}`}>
        <svg className="sc-search__icon" viewBox="0 0 24 24" aria-hidden="true">
          <circle cx="11" cy="11" r="7" />
          <path d="m16.5 16.5 4.5 4.5" />
        </svg>
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Investigate an IP address or domain"
          spellCheck="false"
          autoComplete="off"
          aria-label="IP address or domain"
        />
        {type ? (
          <span className={`sc-search__type ${type === "invalid" ? "is-invalid" : ""}`}>
            {type === "invalid" ? "Unrecognised" : type}
          </span>
        ) : (
          <kbd className="sc-kbd">/</kbd>
        )}
        <button type="submit" className="sc-btn" disabled={loading || !valid}>
          {loading ? <span className="sc-spinner" aria-hidden="true" /> : null}
          {loading ? "Scanning" : "Investigate"}
        </button>
      </form>
      <div className="sc-examples">
        <span>Try</span>
        {["8.8.8.8", "google.com", "1.1.1.1"].map((q) => (
          <button key={q} type="button" className="sc-example sc-mono" onClick={() => run(q)} disabled={loading}>
            {q}
          </button>
        ))}
      </div>
    </section>
  );
}

/* ----------------------------- charts ---------------------------- */
function RiskRing({ score, level }) {
  const r = 58;
  const c = 2 * Math.PI * r;
  return (
    <div className={`sc-ring sc-ring--${level}`} role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg viewBox="0 0 140 140">
        <circle className="sc-ring__track" cx="70" cy="70" r={r} />
        <circle
          className="sc-ring__fill"
          cx="70"
          cy="70"
          r={r}
          strokeDasharray={c}
          strokeDashoffset={c - (score / 100) * c}
        />
      </svg>
      <div className="sc-ring__label">
        <span className="sc-ring__num">{score}</span>
        <span className="sc-muted">/ 100</span>
      </div>
    </div>
  );
}

function ConfidenceGauge({ value }) {
  const v = Math.min(Math.max(value, 0), 100);
  const R = 80;
  const cx = 100;
  const cy = 96;
  const pt = (pct, r = R) => {
    const a = Math.PI * (1 - pct / 100);
    return [cx + r * Math.cos(a), cy - r * Math.sin(a)];
  };
  const arc = (from, to) => {
    const [x1, y1] = pt(from);
    const [x2, y2] = pt(to);
    return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${R} ${R} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
  };
  const level = levelFor(v);
  const [nx, ny] = pt(v, R - 22);

  return (
    <div className="sc-gauge" role="img" aria-label={`Abuse confidence ${v} percent`}>
      <svg viewBox="0 0 200 118">
        <path className="sc-gauge__band sc-gauge__band--good" d={arc(0, 24.5)} />
        <path className="sc-gauge__band sc-gauge__band--warning" d={arc(25.5, 74.5)} />
        <path className="sc-gauge__band sc-gauge__band--critical" d={arc(75.5, 100)} />
        {v > 0 && <path className={`sc-gauge__fill sc-gauge__fill--${level}`} d={arc(0, v)} />}
        <line className="sc-gauge__needle" x1={cx} y1={cy} x2={nx} y2={ny} />
        <circle className="sc-gauge__hub" cx={cx} cy={cy} r="5" />
        <text x="18" y="114" className="sc-gauge__tick">0</text>
        <text x="182" y="114" className="sc-gauge__tick" textAnchor="end">100</text>
      </svg>
      <div className="sc-gauge__value">
        <span className="sc-gauge__num">{v}%</span>
        <span className="sc-label">Abuse Confidence</span>
      </div>
    </div>
  );
}

function DetectionBar({ mal, harm }) {
  const [tip, setTip] = useState(null);
  const total = mal + harm;
  const malPct = total ? (mal / total) * 100 : 0;
  const malW = mal > 0 ? Math.max(malPct, 1.5) : 0;
  const segs = [
    { key: "mal", label: "Malicious", n: mal, pct: malPct, w: malW, cls: "critical" },
    { key: "harm", label: "Harmless", n: harm, pct: 100 - malPct, w: 100 - malW, cls: "good" },
  ].filter((s) => s.n > 0);

  return (
    <div className="sc-dbar">
      <div className="sc-dbar__track" onMouseLeave={() => setTip(null)}>
        {total === 0 && <div className="sc-dbar__empty">No engine results</div>}
        {segs.map((s) => (
          <div
            key={s.key}
            className={`sc-dbar__seg sc-dbar__seg--${s.cls}`}
            style={{ width: `${s.w}%` }}
            onMouseEnter={() => setTip(s)}
            onFocus={() => setTip(s)}
            onBlur={() => setTip(null)}
            tabIndex={0}
            aria-label={`${s.label}: ${s.n} engines, ${s.pct.toFixed(1)}%`}
          />
        ))}
        {tip && (
          <div className="sc-tip" role="tooltip">
            <strong>{tip.label}</strong>
            <span>
              {tip.n} engine{tip.n === 1 ? "" : "s"} · {tip.pct.toFixed(1)}%
            </span>
          </div>
        )}
      </div>
      <div className="sc-legend">
        <span><i className="sc-swatch sc-swatch--critical" /> Malicious <b>{mal}</b></span>
        <span><i className="sc-swatch sc-swatch--good" /> Harmless <b>{harm}</b></span>
      </div>
    </div>
  );
}

function EngineGrid({ mal, harm }) {
  const cells = [
    ...Array.from({ length: mal }, () => "critical"),
    ...Array.from({ length: harm }, () => "good"),
  ];
  if (!cells.length) return null;
  return (
    <div className="sc-engines" aria-hidden="true">
      {cells.map((c, i) => (
        <span
          key={i}
          className={`sc-engine sc-engine--${c}`}
          title={`Engine ${i + 1}: ${c === "critical" ? "Malicious" : "Harmless"}`}
        />
      ))}
    </div>
  );
}

/* ------------------------------ panels --------------------------- */
function Panel({ title, tag, className = "", children, actions }) {
  return (
    <article className={`sc-panel sc-glass ${className}`}>
      <header className="sc-panel__head">
        <div className="sc-panel__title">
          {tag && <span className="sc-tag">{tag}</span>}
          <h2>{title}</h2>
        </div>
        {actions}
      </header>
      {children}
    </article>
  );
}

function VerdictPanel({ threat, data }) {
  const mal = data.virustotal?.malicious_flags ?? 0;
  const conf = data.abuseipdb?.confidence_score ?? 0;
  const summary =
    threat.level === "good"
      ? "No security vendor or abuse reporter has flagged this indicator."
      : `${mal} engine${mal === 1 ? "" : "s"} flagged it as malicious, and the hosting IP has a ${conf}% abuse confidence score.`;
  return (
    <Panel title="Threat Verdict" className={`sc-verdict sc-verdict--${threat.level} sc-span-5`}>
      <div className="sc-verdict__body">
        <RiskRing score={threat.score} level={threat.level} />
        <div className="sc-verdict__text">
          <StatusChip level={threat.level}>{threat.label}</StatusChip>
          <p>{summary}</p>
          <span className="sc-label">Composite risk score</span>
        </div>
      </div>
    </Panel>
  );
}

function TargetPanel({ data, scannedAt }) {
  const [copied, setCopied] = useState(false);
  const cc = data.abuseipdb?.hosting_country;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(data.resolved_ip);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard blocked */
    }
  };
  return (
    <Panel title="Target Profile" className="sc-span-7">
      <dl className="sc-kv">
        <div className="sc-kv__item sc-kv__item--wide">
          <dt className="sc-label">Target Query</dt>
          <dd className="sc-mono sc-kv__big">{data.search_query}</dd>
        </div>
        <div className="sc-kv__item">
          <dt className="sc-label">Search Type</dt>
          <dd>{data.search_type}</dd>
        </div>
        <div className="sc-kv__item">
          <dt className="sc-label">Resolved Infrastructure IP</dt>
          <dd className="sc-mono sc-kv__ip">
            {data.resolved_ip || "N/A"}
            {data.resolved_ip && (
              <button type="button" className="sc-copy" onClick={copy} aria-label="Copy IP">
                {copied ? "Copied" : "Copy"}
              </button>
            )}
          </dd>
        </div>
        <div className="sc-kv__item">
          <dt className="sc-label">Network Provider</dt>
          <dd>{data.virustotal?.network_provider || "Unknown"}</dd>
        </div>
        <div className="sc-kv__item">
          <dt className="sc-label">Hosting Country</dt>
          <dd className="sc-kv__country">
            <Flag code={cc} />
            {cc ? countryName(cc) : "Unknown"}
          </dd>
        </div>
        <div className="sc-kv__item">
          <dt className="sc-label">Scanned</dt>
          <dd className="sc-mono">{timeUTC(scannedAt)}</dd>
        </div>
      </dl>
    </Panel>
  );
}

function KpiRow({ data }) {
  const mal = data.virustotal?.malicious_flags ?? 0;
  const harm = data.virustotal?.harmless_flags ?? 0;
  const conf = data.abuseipdb?.confidence_score ?? 0;
  const reports = data.abuseipdb?.total_reports ?? 0;
  const tiles = [
    { label: "Malicious Detections", value: mal, level: levelFor(mal, 5), note: `of ${mal + harm} engines` },
    { label: "Harmless Verdicts", value: harm, level: "info", note: "VirusTotal engines" },
    { label: "Abuse Confidence", value: `${conf}%`, level: levelFor(conf), note: "AbuseIPDB score" },
    { label: "Historical Reports", value: reports.toLocaleString(), level: reports > 0 ? "warning" : "good", note: "AbuseIPDB reports" },
  ];
  return (
    <section className="sc-kpis sc-span-12">
      {tiles.map((t) => (
        <div key={t.label} className={`sc-kpi sc-glass sc-kpi--${t.level}`}>
          <div className="sc-kpi__top">
            <span className="sc-label">{t.label}</span>
            <StatusIcon level={t.level} size={16} />
          </div>
          <span className="sc-kpi__value">{t.value}</span>
          <span className="sc-muted sc-small">{t.note}</span>
        </div>
      ))}
    </section>
  );
}

function VirusTotalPanel({ vt }) {
  const mal = vt?.malicious_flags ?? 0;
  const harm = vt?.harmless_flags ?? 0;
  const total = mal + harm;
  return (
    <Panel title="VirusTotal Engine Analytics" tag="VT" className="sc-span-7">
      <div className="sc-vt__ratio">
        <span className="sc-vt__big">
          {mal}
          <span className="sc-muted">/{total}</span>
        </span>
        <span className="sc-label">Detection ratio</span>
      </div>
      <DetectionBar mal={mal} harm={harm} />
      <div className="sc-sub">
        <span className="sc-label">Per-engine verdicts</span>
        <EngineGrid mal={mal} harm={harm} />
      </div>
      <div className="sc-foot">
        <span className="sc-label">Network / Registry Provider</span>
        <span className="sc-strong">{vt?.network_provider || "Unknown"}</span>
      </div>
    </Panel>
  );
}

function AbusePanel({ abuse }) {
  const conf = abuse?.confidence_score ?? 0;
  const reports = abuse?.total_reports ?? 0;
  const cc = abuse?.hosting_country;
  return (
    <Panel title="AbuseIPDB Infrastructure" tag="AB" className="sc-span-5">
      <ConfidenceGauge value={conf} />
      <div className="sc-gauge__legend">
        <span><i className="sc-swatch sc-swatch--good" /> Low 0-24</span>
        <span><i className="sc-swatch sc-swatch--warning" /> Medium 25-74</span>
        <span><i className="sc-swatch sc-swatch--critical" /> High 75+</span>
      </div>
      <div className="sc-abuse__stats">
        <div>
          <span className="sc-label">Historical Reports</span>
          <span className="sc-abuse__num">{reports.toLocaleString()}</span>
        </div>
        <div>
          <span className="sc-label">Hosting Country</span>
          <span className="sc-abuse__country">
            <Flag code={cc} />
            {cc ? countryName(cc) : "Unknown"}
          </span>
        </div>
      </div>
    </Panel>
  );
}

function SignalsPanel({ data }) {
  const mal = data.virustotal?.malicious_flags ?? 0;
  const conf = data.abuseipdb?.confidence_score ?? 0;
  const reports = data.abuseipdb?.total_reports ?? 0;
  const signals = [
    {
      level: mal >= 5 ? "critical" : mal > 0 ? "warning" : "good",
      title: "Vendor detections",
      text: mal > 0 ? `${mal} VirusTotal engine${mal === 1 ? "" : "s"} report this indicator as malicious.` : "No VirusTotal engine reports this indicator as malicious.",
    },
    {
      level: levelFor(conf),
      title: "Abuse confidence",
      text: conf > 0 ? `AbuseIPDB rates the hosting IP ${conf}% likely to be abusive.` : "AbuseIPDB has no abuse confidence against the hosting IP.",
    },
    {
      level: reports > 0 ? "warning" : "good",
      title: "Report history",
      text: reports > 0 ? `${reports.toLocaleString()} abuse report${reports === 1 ? "" : "s"} filed against this IP.` : "No abuse reports on record for this IP.",
    },
    {
      level: data.resolved_ip ? "info" : "warning",
      title: "Infrastructure",
      text: data.resolved_ip
        ? `Hosted on ${data.resolved_ip}${data.virustotal?.network_provider ? ` (${data.virustotal.network_provider})` : ""}.`
        : "The hosting IP could not be resolved.",
    },
  ];
  return (
    <Panel title="Signal Breakdown" className="sc-span-7">
      <ul className="sc-signals">
        {signals.map((s) => (
          <li key={s.title} className={`sc-signal sc-signal--${s.level}`}>
            <StatusIcon level={s.level} size={18} />
            <div>
              <span className="sc-strong">{s.title}</span>
              <p>{s.text}</p>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function HistoryPanel({ history, onPick, loading }) {
  return (
    <Panel title="Recent Investigations" className="sc-span-5">
      {history.length === 0 ? (
        <p className="sc-muted sc-small">Lookups from this session appear here.</p>
      ) : (
        <ul className="sc-history">
          {history.map((h) => (
            <li key={h.query}>
              <button type="button" onClick={() => onPick(h.query)} disabled={loading}>
                <StatusIcon level={h.level} size={16} />
                <span className="sc-mono sc-history__q">{h.query}</span>
                <span className="sc-history__score">{h.score}</span>
                <span className="sc-muted sc-small">{h.time}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function AlertBanner({ threat, data }) {
  if (threat.level === "good") return null;
  const mal = data.virustotal?.malicious_flags ?? 0;
  const conf = data.abuseipdb?.confidence_score ?? 0;
  return (
    <section className={`sc-alert sc-alert--${threat.level} sc-span-12`} role="alert">
      <StatusIcon level={threat.level} size={22} />
      <div>
        <strong>{threat.level === "critical" ? "High-risk indicator detected" : "Potential threat indicator"}</strong>
        <p>
          {mal > 0 && `${mal} VirusTotal engine${mal === 1 ? "" : "s"} flagged this target. `}
          {conf > 0 && `AbuseIPDB confidence is ${conf}%. `}
          Review before allowing traffic to or from this infrastructure.
        </p>
      </div>
    </section>
  );
}

function RawJson({ data }) {
  return (
    <details className="sc-raw sc-glass sc-span-12">
      <summary>View raw API response</summary>
      <pre className="sc-mono">{JSON.stringify(data, null, 2)}</pre>
    </details>
  );
}

function LoadingView({ query }) {
  return (
    <div className="sc-grid" aria-live="polite">
      <div className="sc-scanning sc-glass sc-span-12">
        <span className="sc-scanning__pulse" />
        <span>
          Querying VirusTotal and AbuseIPDB for <b className="sc-mono">{query}</b>
        </span>
        <span className="sc-scanning__line" />
      </div>
      <div className="sc-panel sc-glass sc-skel sc-span-5" />
      <div className="sc-panel sc-glass sc-skel sc-span-7" />
      <div className="sc-panel sc-glass sc-skel sc-skel--short sc-span-12" />
      <div className="sc-panel sc-glass sc-skel sc-span-7" />
      <div className="sc-panel sc-glass sc-skel sc-span-5" />
    </div>
  );
}

function EmptyView() {
  const steps = [
    ["Enter an indicator", "Paste an IPv4, IPv6 address or a domain name."],
    ["Multi-vendor lookup", "VirusTotal engines and AbuseIPDB reports are checked together."],
    ["Get a verdict", "A single risk score with the signals behind it."],
  ];
  return (
    <section className="sc-empty sc-glass">
      {steps.map(([t, d], i) => (
        <div key={t} className="sc-empty__step">
          <span className="sc-empty__n">{i + 1}</span>
          <span className="sc-strong">{t}</span>
          <span className="sc-muted sc-small">{d}</span>
        </div>
      ))}
    </section>
  );
}

/* --------------------------- main view --------------------------- */
export default function ThreatDashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState("");
  const [scannedAt, setScannedAt] = useState(null);
  const [history, setHistory] = useState([]);
  const abortRef = useRef(null);

  const runSearch = useCallback(async (query) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setLoading(true);
    setError("");
    setPending(query);

    try {
      const res = await fetch(`${API_URL}?${QUERY_PARAM}=${encodeURIComponent(query)}`, {
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
      const isJson = (res.headers.get("content-type") || "").includes("application/json");
      const body = isJson ? await res.json() : null;

      if (!res.ok) throw new Error(body?.error || `The API responded with status ${res.status}.`);
      if (!body)
        throw new Error(
          "The API did not return JSON. Locally, check Flask is running on port 8080 and the Vite proxy is set up."
        );

      const now = new Date();
      const t = assessThreat(body);
      setData(body);
      setScannedAt(now);
      setHistory((h) =>
        [
          { query: body.search_query || query, level: t.level, score: t.score, time: timeUTC(now).slice(0, 5) },
          ...h.filter((x) => x.query !== (body.search_query || query)),
        ].slice(0, 6)
      );
    } catch (err) {
      if (err.name === "AbortError") return;
      setData(null);
      setError(
        err.message === "Failed to fetch"
          ? "Couldn't reach the API. Check the backend is running."
          : err.message
      );
    } finally {
      if (abortRef.current === controller) setLoading(false);
    }
  }, []);

  const threat = data ? assessThreat(data) : null;

  return (
    <div className="sc-app">
      <style>{STYLES}</style>
      <div className="sc-bg" aria-hidden="true">
        <span className="sc-blob sc-blob--a" />
        <span className="sc-blob sc-blob--b" />
        <span className="sc-blob sc-blob--c" />
      </div>

      <div className="sc-shell">
        <TopBar />
        <CommandBar onSearch={runSearch} loading={loading} />

        {error && (
          <div className="sc-error sc-glass" role="alert">
            <StatusIcon level="critical" size={18} />
            <span><strong>Lookup failed.</strong> {error}</span>
          </div>
        )}

        {loading && <LoadingView query={pending} />}

        {!loading && data && (
          <div className="sc-grid sc-results">
            <AlertBanner threat={threat} data={data} />
            <VerdictPanel threat={threat} data={data} />
            <TargetPanel data={data} scannedAt={scannedAt} />
            <KpiRow data={data} />
            <VirusTotalPanel vt={data.virustotal} />
            <AbusePanel abuse={data.abuseipdb} />
            <SignalsPanel data={data} />
            <HistoryPanel history={history} onPick={runSearch} loading={loading} />
            <RawJson data={data} />
          </div>
        )}

        {!loading && !data && !error && <EmptyView />}
      </div>
    </div>
  );
}

/* ----------------------------- styles ---------------------------- */
const STYLES = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

.sc-app {
  --ink: #0f172a;
  --ink-2: #334155;
  --muted: #64748b;
  --line: rgba(15, 23, 42, 0.08);
  --glass: rgba(255, 255, 255, 0.62);
  --glass-strong: rgba(255, 255, 255, 0.8);
  --glass-border: rgba(255, 255, 255, 0.85);
  --accent: #2dd4bf;
  --accent-deep: #0f766e;
  --good: #0ca30c;
  --good-ink: #0a6b0a;
  --warning: #fab219;
  --warning-ink: #8a5a00;
  --critical: #d03b3b;
  --critical-ink: #a82828;
  --info: #64748b;
  --radius: 20px;
  --shadow: 0 1px 0 rgba(255,255,255,0.9) inset, 0 18px 40px -20px rgba(15, 23, 42, 0.22), 0 2px 6px -2px rgba(15, 23, 42, 0.06);
  --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Consolas, monospace;

  position: relative;
  min-height: 100vh;
  background: linear-gradient(160deg, #f4f7fb 0%, #eaf0f7 50%, #eef3f1 100%);
  color: var(--ink);
  font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.5;
  padding: 20px 16px 64px;
  box-sizing: border-box;
  overflow-x: hidden;
}
.sc-app *, .sc-app *::before, .sc-app *::after { box-sizing: border-box; }
.sc-app p { margin: 0; }
.sc-app button { font-family: inherit; }

/* ambient background */
.sc-bg { position: fixed; inset: 0; pointer-events: none; overflow: hidden; }
.sc-blob { position: absolute; border-radius: 50%; filter: blur(80px); opacity: 0.55; }
.sc-blob--a { width: 520px; height: 520px; background: #99f6e4; top: -180px; left: -120px; }
.sc-blob--b { width: 460px; height: 460px; background: #c7d2fe; top: 20%; right: -160px; }
.sc-blob--c { width: 420px; height: 420px; background: #fde2e4; bottom: -200px; left: 30%; opacity: 0.4; }

.sc-shell { position: relative; max-width: 1200px; margin: 0 auto; }

/* glass */
.sc-glass {
  background: var(--glass);
  -webkit-backdrop-filter: blur(20px) saturate(160%);
  backdrop-filter: blur(20px) saturate(160%);
  border: 1px solid var(--glass-border);
  box-shadow: var(--shadow);
}

/* type helpers */
.sc-label { display: block; font-size: 11px; font-weight: 600; letter-spacing: 0.07em; text-transform: uppercase; color: var(--muted); }
.sc-muted { color: var(--muted); }
.sc-small { font-size: 12.5px; }
.sc-strong { font-weight: 600; color: var(--ink); }
.sc-mono { font-family: var(--mono); }

/* top bar */
.sc-topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 12px 18px; border-radius: 16px; margin-bottom: 36px;
}
.sc-brand { display: flex; align-items: center; gap: 12px; }
.sc-brand__mark {
  width: 36px; height: 36px; border-radius: 11px; display: grid; place-items: center;
  background: linear-gradient(135deg, #5eead4, #2dd4bf); stroke: #042f2e;
  box-shadow: 0 6px 16px -6px rgba(45, 212, 191, 0.8);
}
.sc-brand__mark svg { stroke: #042f2e; }
.sc-brand__name { display: block; font-weight: 700; font-size: 15px; letter-spacing: -0.01em; }
.sc-brand__sub { display: block; font-size: 12px; color: var(--muted); }
.sc-topbar__meta { display: flex; align-items: center; gap: 14px; font-size: 12.5px; color: var(--ink-2); }
.sc-sources { display: inline-flex; align-items: center; gap: 8px; }
.sc-live { width: 8px; height: 8px; border-radius: 50%; background: var(--good); box-shadow: 0 0 0 0 rgba(12,163,12,0.5); animation: sc-ping 2s infinite; }
@keyframes sc-ping { 0% { box-shadow: 0 0 0 0 rgba(12,163,12,0.45); } 70% { box-shadow: 0 0 0 7px rgba(12,163,12,0); } 100% { box-shadow: 0 0 0 0 rgba(12,163,12,0); } }
.sc-clock { padding: 4px 10px; border-radius: 8px; background: var(--glass-strong); border: 1px solid var(--line); }

/* command bar */
.sc-command { max-width: 820px; margin: 0 auto 36px; }
.sc-search {
  display: flex; align-items: center; gap: 10px;
  border-radius: 18px; padding: 8px 8px 8px 18px;
  transition: box-shadow 0.2s, border-color 0.2s;
}
.sc-search:focus-within { border-color: #5eead4; box-shadow: var(--shadow), 0 0 0 5px rgba(45, 212, 191, 0.18); }
.sc-search.is-invalid:focus-within { border-color: #fcd34d; box-shadow: var(--shadow), 0 0 0 5px rgba(250, 178, 25, 0.18); }
.sc-search__icon { width: 20px; height: 20px; flex: none; fill: none; stroke: var(--muted); stroke-width: 2; stroke-linecap: round; }
.sc-search input {
  flex: 1; min-width: 0; border: 0; outline: 0; background: transparent;
  font-family: var(--mono); font-size: 16px; color: var(--ink); padding: 12px 0;
}
.sc-search input::placeholder { font-family: Inter, system-ui, sans-serif; color: #94a3b8; }
.sc-search__type {
  flex: none; font-size: 11.5px; font-weight: 600; padding: 4px 9px; border-radius: 7px;
  background: rgba(45, 212, 191, 0.16); color: var(--accent-deep);
}
.sc-search__type.is-invalid { background: rgba(250, 178, 25, 0.18); color: var(--warning-ink); }
.sc-kbd {
  flex: none; font-family: var(--mono); font-size: 12px; color: var(--muted);
  border: 1px solid var(--line); border-bottom-width: 2px; border-radius: 6px; padding: 1px 7px; background: #fff;
}
.sc-btn {
  flex: none; display: inline-flex; align-items: center; gap: 8px;
  border: 0; border-radius: 13px; padding: 13px 22px; cursor: pointer;
  background: linear-gradient(135deg, #5eead4, #2dd4bf);
  color: #042f2e; font-weight: 700; font-size: 14px;
  box-shadow: 0 8px 22px -8px rgba(45, 212, 191, 0.9);
  transition: transform 0.12s, box-shadow 0.2s, filter 0.2s;
}
.sc-btn:hover:not(:disabled) { transform: translateY(-1px); filter: brightness(1.05); box-shadow: 0 12px 26px -8px rgba(45, 212, 191, 1); }
.sc-btn:disabled { opacity: 0.85; box-shadow: none; cursor: not-allowed; }
.sc-spinner { width: 14px; height: 14px; border-radius: 50%; border: 2px solid rgba(4,47,46,0.25); border-top-color: #042f2e; animation: sc-spin 0.8s linear infinite; }
@keyframes sc-spin { to { transform: rotate(360deg); } }
.sc-examples { display: flex; flex-wrap: wrap; align-items: center; justify-content: center; gap: 8px; margin-top: 14px; font-size: 12.5px; color: var(--muted); }
.sc-example {
  border: 1px solid var(--glass-border); background: var(--glass); border-radius: 999px;
  padding: 4px 12px; font-size: 12.5px; color: var(--ink-2); cursor: pointer; transition: background 0.15s;
}
.sc-example:hover:not(:disabled) { background: #fff; }

/* grid */
.sc-grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 16px; }
.sc-span-12 { grid-column: span 12; }
.sc-span-7 { grid-column: span 7; }
.sc-span-5 { grid-column: span 5; }
.sc-results > * { animation: sc-rise 0.45s cubic-bezier(.2,.7,.2,1) both; }
.sc-results > *:nth-child(2) { animation-delay: 0.04s; }
.sc-results > *:nth-child(3) { animation-delay: 0.08s; }
.sc-results > *:nth-child(4) { animation-delay: 0.12s; }
.sc-results > *:nth-child(5) { animation-delay: 0.16s; }
.sc-results > *:nth-child(6) { animation-delay: 0.2s; }
.sc-results > *:nth-child(n+7) { animation-delay: 0.24s; }
@keyframes sc-rise { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }

/* panels */
.sc-panel { border-radius: var(--radius); padding: 22px; min-width: 0; }
.sc-panel__head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px; }
.sc-panel__title { display: flex; align-items: center; gap: 10px; }
.sc-panel__title h2 { margin: 0; font-size: 14.5px; font-weight: 650; letter-spacing: -0.005em; }
.sc-tag {
  font-family: var(--mono); font-size: 10.5px; font-weight: 600; color: var(--accent-deep);
  background: rgba(45, 212, 191, 0.14); border-radius: 6px; padding: 3px 6px;
}

/* status chips + icons */
.sc-ico--good { stroke: var(--good); }
.sc-ico--warning { stroke: #d99400; }
.sc-ico--critical { stroke: var(--critical); }
.sc-ico--info { stroke: var(--info); }
.sc-chip {
  display: inline-flex; align-items: center; gap: 6px; width: fit-content;
  font-size: 12.5px; font-weight: 650; padding: 5px 11px 5px 9px; border-radius: 999px;
}
.sc-chip--good { background: rgba(12, 163, 12, 0.1); color: var(--good-ink); }
.sc-chip--warning { background: rgba(250, 178, 25, 0.18); color: var(--warning-ink); }
.sc-chip--critical { background: rgba(208, 59, 59, 0.1); color: var(--critical-ink); }

/* alert */
.sc-alert {
  display: flex; gap: 14px; align-items: flex-start; border-radius: 16px; padding: 16px 20px;
  -webkit-backdrop-filter: blur(20px); backdrop-filter: blur(20px);
}
.sc-alert--warning { background: rgba(254, 243, 199, 0.72); border: 1px solid rgba(250, 178, 25, 0.45); }
.sc-alert--critical { background: rgba(254, 226, 226, 0.72); border: 1px solid rgba(208, 59, 59, 0.35); }
.sc-alert strong { display: block; font-size: 14.5px; margin-bottom: 2px; }
.sc-alert p { color: var(--ink-2); }
.sc-alert svg { flex: none; margin-top: 1px; }

/* verdict */
.sc-verdict { position: relative; overflow: hidden; }
.sc-verdict::before {
  content: ""; position: absolute; inset: 0 auto 0 0; width: 4px;
}
.sc-verdict--good::before { background: var(--good); }
.sc-verdict--warning::before { background: var(--warning); }
.sc-verdict--critical::before { background: var(--critical); }
.sc-verdict__body { display: flex; align-items: center; gap: 22px; }
.sc-verdict__text { display: grid; gap: 10px; }
.sc-verdict__text p { color: var(--ink-2); }

.sc-ring { position: relative; width: 140px; height: 140px; flex: none; }
.sc-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.sc-ring__track { fill: none; stroke: rgba(15, 23, 42, 0.07); stroke-width: 10; }
.sc-ring__fill { fill: none; stroke-width: 10; stroke-linecap: round; transition: stroke-dashoffset 0.9s cubic-bezier(.2,.7,.2,1); }
.sc-ring--good .sc-ring__fill { stroke: var(--good); }
.sc-ring--warning .sc-ring__fill { stroke: var(--warning); }
.sc-ring--critical .sc-ring__fill { stroke: var(--critical); }
.sc-ring__label { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.sc-ring__num { font-size: 38px; font-weight: 800; letter-spacing: -0.03em; line-height: 1; font-variant-numeric: tabular-nums; }

/* target profile */
.sc-kv { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px 20px; margin: 0; }
.sc-kv__item { min-width: 0; }
.sc-kv__item--wide { grid-column: 1 / -1; padding-bottom: 14px; border-bottom: 1px solid var(--line); }
.sc-kv dd { margin: 4px 0 0; font-weight: 600; overflow-wrap: anywhere; }
.sc-kv__big { font-size: 20px; letter-spacing: -0.01em; }
.sc-kv__ip, .sc-kv__country { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.sc-copy {
  font-family: Inter, system-ui, sans-serif; font-size: 11px; font-weight: 600; cursor: pointer;
  border: 1px solid var(--line); background: #fff; color: var(--ink-2); border-radius: 6px; padding: 2px 8px;
}
.sc-copy:hover { border-color: #5eead4; }
.sc-flag { width: 28px; height: 20px; border-radius: 4px; object-fit: cover; box-shadow: 0 0 0 1px var(--line); flex: none; }
.sc-flag--text { display: inline-grid; place-items: center; font-size: 10px; font-weight: 700; background: #fff; color: var(--muted); }

/* KPI tiles */
.sc-kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
.sc-kpi { border-radius: 16px; padding: 16px 18px; display: grid; gap: 4px; position: relative; overflow: hidden; }
.sc-kpi__top { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.sc-kpi__value { font-size: 30px; font-weight: 750; letter-spacing: -0.02em; line-height: 1.15; font-variant-numeric: tabular-nums; }

/* VirusTotal */
.sc-vt__ratio { display: flex; align-items: baseline; gap: 12px; margin-bottom: 14px; }
.sc-vt__big { font-size: 34px; font-weight: 800; letter-spacing: -0.03em; font-variant-numeric: tabular-nums; }
.sc-vt__big .sc-muted { font-size: 20px; font-weight: 600; }
.sc-dbar__track {
  position: relative; display: flex; gap: 2px; height: 16px; border-radius: 6px;
  background: rgba(15, 23, 42, 0.06);
}
.sc-dbar__seg { height: 100%; cursor: default; outline: none; transition: width 0.7s cubic-bezier(.2,.7,.2,1), filter 0.15s; }
.sc-dbar__seg:first-child { border-radius: 6px 0 0 6px; }
.sc-dbar__seg:last-child { border-radius: 0 6px 6px 0; }
.sc-dbar__seg:only-child { border-radius: 6px; }
.sc-dbar__seg:hover, .sc-dbar__seg:focus-visible { filter: brightness(1.1) saturate(1.1); }
.sc-dbar__seg--critical { background: var(--critical); }
.sc-dbar__seg--good { background: var(--good); }
.sc-dbar__empty { font-size: 11px; color: var(--muted); padding-left: 8px; line-height: 16px; }
.sc-tip {
  position: absolute; bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%);
  display: grid; gap: 2px; white-space: nowrap; pointer-events: none; z-index: 5;
  background: rgba(15, 23, 42, 0.92); color: #fff; font-size: 12px; padding: 7px 10px; border-radius: 8px;
  box-shadow: 0 8px 20px -8px rgba(15, 23, 42, 0.5);
}
.sc-tip span { color: #cbd5e1; }
.sc-legend, .sc-gauge__legend { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 10px; font-size: 12.5px; color: var(--ink-2); }
.sc-legend b { font-weight: 700; color: var(--ink); margin-left: 2px; }
.sc-swatch { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }
.sc-swatch--good { background: var(--good); }
.sc-swatch--warning { background: var(--warning); }
.sc-swatch--critical { background: var(--critical); }
.sc-sub { margin-top: 20px; }
.sc-engines { display: flex; flex-wrap: wrap; gap: 3px; margin-top: 10px; }
.sc-engine { width: 11px; height: 11px; border-radius: 3px; transition: transform 0.12s; }
.sc-engine:hover { transform: scale(1.35); }
.sc-engine--critical { background: var(--critical); }
.sc-engine--good { background: rgba(12, 163, 12, 0.55); }
.sc-foot { margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--line); display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }

/* AbuseIPDB gauge */
.sc-gauge { position: relative; max-width: 300px; margin: 0 auto; }
.sc-gauge svg { width: 100%; display: block; }
.sc-gauge__band { fill: none; stroke-width: 14; opacity: 0.18; }
.sc-gauge__band--good { stroke: var(--good); }
.sc-gauge__band--warning { stroke: var(--warning); }
.sc-gauge__band--critical { stroke: var(--critical); }
.sc-gauge__fill { fill: none; stroke-width: 14; stroke-linecap: round; }
.sc-gauge__fill--good { stroke: var(--good); }
.sc-gauge__fill--warning { stroke: var(--warning); }
.sc-gauge__fill--critical { stroke: var(--critical); }
.sc-gauge__needle { stroke: var(--ink); stroke-width: 2.5; stroke-linecap: round; }
.sc-gauge__hub { fill: var(--ink); }
.sc-gauge__tick { font-size: 9px; fill: var(--muted); font-family: Inter, system-ui, sans-serif; }
.sc-gauge__value { text-align: center; margin-top: -6px; }
.sc-gauge__num { display: block; font-size: 30px; font-weight: 800; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.sc-gauge__legend { justify-content: center; }
.sc-abuse__stats { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--line); }
.sc-abuse__num { display: block; font-size: 24px; font-weight: 750; margin-top: 2px; font-variant-numeric: tabular-nums; }
.sc-abuse__country { display: flex; align-items: center; gap: 8px; font-weight: 600; margin-top: 6px; }

/* signals */
.sc-signals { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
.sc-signal { display: flex; gap: 12px; align-items: flex-start; padding: 12px 14px; border-radius: 12px; background: rgba(255,255,255,0.55); border: 1px solid var(--line); }
.sc-signal svg { flex: none; margin-top: 1px; }
.sc-signal p { color: var(--ink-2); font-size: 13px; margin-top: 1px; }

/* history */
.sc-history { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.sc-history button {
  width: 100%; display: grid; grid-template-columns: auto 1fr auto auto; align-items: center; gap: 10px;
  text-align: left; border: 1px solid transparent; background: transparent; border-radius: 10px;
  padding: 9px 10px; cursor: pointer; color: var(--ink); transition: background 0.15s, border-color 0.15s;
}
.sc-history button:hover:not(:disabled) { background: rgba(255,255,255,0.7); border-color: var(--line); }
.sc-history__q { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
.sc-history__score { font-weight: 700; font-variant-numeric: tabular-nums; }

/* raw json */
.sc-raw { border-radius: 16px; padding: 14px 18px; }
.sc-raw summary { cursor: pointer; font-weight: 600; font-size: 13px; color: var(--ink-2); }
.sc-raw pre { margin: 12px 0 0; padding: 14px; border-radius: 10px; background: rgba(15, 23, 42, 0.04); font-size: 12.5px; overflow-x: auto; }

/* loading */
.sc-scanning {
  position: relative; overflow: hidden; display: flex; align-items: center; gap: 12px;
  border-radius: 16px; padding: 16px 20px; color: var(--ink-2);
}
.sc-scanning__pulse { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); animation: sc-ping-t 1.4s infinite; flex: none; }
@keyframes sc-ping-t { 0% { box-shadow: 0 0 0 0 rgba(45,212,191,0.6); } 70% { box-shadow: 0 0 0 10px rgba(45,212,191,0); } 100% { box-shadow: 0 0 0 0 rgba(45,212,191,0); } }
.sc-scanning__line {
  position: absolute; left: 0; bottom: 0; height: 2px; width: 30%;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  animation: sc-scan 1.4s ease-in-out infinite;
}
@keyframes sc-scan { from { transform: translateX(-100%); } to { transform: translateX(340%); } }
.sc-skel { height: 220px; position: relative; overflow: hidden; }
.sc-skel--short { height: 110px; }
.sc-skel::after {
  content: ""; position: absolute; inset: 0;
  background: linear-gradient(100deg, transparent 20%, rgba(255,255,255,0.75) 50%, transparent 80%);
  animation: sc-shimmer 1.4s infinite;
}
@keyframes sc-shimmer { from { transform: translateX(-100%); } to { transform: translateX(100%); } }

/* empty + error */
.sc-empty { max-width: 820px; margin: 0 auto; border-radius: var(--radius); padding: 26px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 22px; }
.sc-empty__step { display: grid; gap: 6px; align-content: start; }
.sc-empty__n {
  width: 28px; height: 28px; border-radius: 9px; display: grid; place-items: center; margin-bottom: 4px;
  font-weight: 700; font-size: 13px; color: var(--accent-deep); background: rgba(45, 212, 191, 0.16);
}
.sc-error {
  max-width: 820px; margin: 0 auto 20px; display: flex; gap: 10px; align-items: flex-start;
  border-radius: 14px; padding: 14px 18px; color: var(--critical-ink);
  background: rgba(254, 226, 226, 0.7); border-color: rgba(208, 59, 59, 0.3);
}
.sc-error svg { flex: none; margin-top: 1px; }

/* responsive */
@media (max-width: 980px) {
  .sc-span-7, .sc-span-5 { grid-column: span 12; }
  .sc-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 640px) {
  .sc-topbar { flex-wrap: wrap; }
  .sc-sources { display: none; }
  .sc-search { flex-wrap: wrap; padding: 8px 8px 8px 14px; }
  .sc-search__type, .sc-kbd { display: none; }
  .sc-btn { width: 100%; justify-content: center; }
  .sc-verdict__body { flex-direction: column; align-items: flex-start; }
  .sc-kv { grid-template-columns: 1fr 1fr; }
  .sc-kpi__value { font-size: 24px; }
  .sc-empty { grid-template-columns: 1fr; }
  .sc-panel { padding: 18px; }
}
@media (prefers-reduced-motion: reduce) {
  .sc-app * { animation: none !important; transition: none !important; }
}
`;