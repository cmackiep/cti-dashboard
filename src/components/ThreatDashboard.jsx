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
  if (IPV4.test(v) || IPV6.test(v)) return "IP address";
  if (DOMAIN.test(v)) return "Domain";
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
  if (score >= 75) return { level: "critical", label: "High risk", score };
  if (score > 0) return { level: "warning", label: "Suspicious", score };
  return { level: "good", label: "Clean", score };
}

function levelFor(value, high = 75) {
  if (value >= high) return "critical";
  if (value > 0) return "warning";
  return "good";
}

const timeUTC = (d) => d.toISOString().slice(11, 19) + " UTC";

const LEVEL_WORD = { good: "Clean", warning: "Suspicious", critical: "High risk", info: "Info" };

/* ------------------------------ bits ----------------------------- */
function Mark({ level, size = 18 }) {
  const glyph = { critical: "!", warning: "?", good: "✓", info: "i" }[level] || "i";
  return (
    <span
      className={`nb-mark nb-mark--${level}`}
      style={{ width: size, height: size, fontSize: size * 0.62 }}
      aria-hidden="true"
    >
      {glyph}
    </span>
  );
}

function Flag({ code }) {
  const [failed, setFailed] = useState(false);
  if (!code || code.length !== 2 || failed)
    return <span className="nb-flag nb-flag--text">{code || "??"}</span>;
  return (
    <img
      className="nb-flag"
      src={`https://flagcdn.com/w40/${code.toLowerCase()}.png`}
      alt=""
      width="30"
      height="20"
      onError={() => setFailed(true)}
    />
  );
}

/* ----------------------------- ticker ---------------------------- */
function Ticker({ history }) {
  if (!history.length) return null;
  const items = history.map((h) => ({ text: `${h.query} ${LEVEL_WORD[h.level]} ${h.score}/100`, level: h.level }));
  // Repeat the list so the strip is always wider than the screen, then double it for a seamless loop.
  const row = [];
  while (row.length < 10) row.push(...items);
  const loop = [...row, ...row];
  return (
    <div className="nb-ticker" aria-hidden="true">
      <div className="nb-ticker__track">
        {loop.map((it, i) => (
          <span key={i} className="nb-ticker__item">
            <span className="nb-ticker__star">★</span>
            {it.level && <i className={`nb-dot nb-dot--${it.level}`} />}
            {it.text}
          </span>
        ))}
      </div>
    </div>
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
    <header className="nb-top">
      <div className="nb-brand">
        <span className="nb-brand__mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </span>
        <span className="nb-brand__name">CTI Console</span>
      </div>
      <span className="nb-clock">{timeUTC(now)}</span>
    </header>
  );
}

/* ------------------------------ hero ----------------------------- */
function Hero({ onSearch, loading, full }) {
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
    <section className={`nb-hero ${full ? "nb-hero--full" : ""}`}>
      <h1 className="nb-hero__title">Is this indicator safe?</h1>

      <form onSubmit={submit} className={`nb-search ${type === "invalid" ? "is-invalid" : ""}`}>
        <label htmlFor="nb-q" className="nb-sr">IP address or domain</label>
        <input
          id="nb-q"
          ref={inputRef}
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Paste an IP address or domain to check it"
          spellCheck="false"
          autoComplete="off"
        />
        {type && (
          <span className={`nb-search__type ${type === "invalid" ? "is-invalid" : ""}`}>
            {type === "invalid" ? "Not an IP or domain" : type}
          </span>
        )}
        <button type="submit" className="nb-btn" disabled={loading || !valid}>
          {loading ? "Checking" : "Investigate"}
        </button>
      </form>

      <div className="nb-try">
        <span>Try</span>
        {["8.8.8.8", "google.com", "1.1.1.1"].map((q) => (
          <button key={q} type="button" className="nb-chip" onClick={() => run(q)} disabled={loading}>
            {q}
          </button>
        ))}
      </div>
    </section>
  );
}

/* ----------------------------- verdict --------------------------- */
function VerdictBand({ threat, data }) {
  const mal = data.virustotal?.malicious_flags ?? 0;
  const conf = data.abuseipdb?.confidence_score ?? 0;
  const summary =
    threat.level === "good"
      ? "No security vendor or abuse reporter has flagged this indicator."
      : `${mal} engine${mal === 1 ? "" : "s"} flagged it as malicious, and the hosting IP has a ${conf}% abuse confidence score.`;
  return (
    <section className={`nb-verdict nb-verdict--${threat.level}`} role={threat.level === "good" ? undefined : "alert"}>
      <div className="nb-verdict__inner">
        <div className="nb-verdict__main">
          <p className="nb-verdict__query">{data.search_query}</p>
          <h2 className="nb-verdict__word">{threat.label}</h2>
          <p className="nb-verdict__summary">{summary}</p>
        </div>
        <div className="nb-stamp" aria-label={`Risk score ${threat.score} out of 100`}>
          <span className="nb-stamp__num">{threat.score}</span>
          <span className="nb-stamp__of">out of 100 risk</span>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------ tiles ---------------------------- */
function Tiles({ data }) {
  const mal = data.virustotal?.malicious_flags ?? 0;
  const harm = data.virustotal?.harmless_flags ?? 0;
  const conf = data.abuseipdb?.confidence_score ?? 0;
  const reports = data.abuseipdb?.total_reports ?? 0;
  const tiles = [
    { label: "Malicious detections", value: mal, level: levelFor(mal, 5), note: `out of ${mal + harm} engines` },
    { label: "Harmless verdicts", value: harm, level: "info", note: "VirusTotal engines" },
    { label: "Abuse confidence", value: `${conf}%`, level: levelFor(conf), note: "AbuseIPDB score" },
    { label: "Abuse reports", value: reports.toLocaleString(), level: reports > 0 ? "warning" : "good", note: "Last 90 days" },
  ];
  return (
    <div className="nb-tiles">
      {tiles.map((t) => (
        <div key={t.label} className="nb-card nb-tile">
          <div className="nb-tile__top">
            <span className="nb-tile__label">{t.label}</span>
            <Mark level={t.level} size={22} />
          </div>
          <span className="nb-tile__value">{t.value}</span>
          <span className="nb-tile__note">{t.note}</span>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------ panels --------------------------- */
function Panel({ title, source, className = "", children }) {
  return (
    <article className={`nb-card nb-panel ${className}`}>
      <header className="nb-panel__head">
        <h3>{title}</h3>
        {source && <span className="nb-tag">{source}</span>}
      </header>
      <div className="nb-panel__body">{children}</div>
    </article>
  );
}

function TargetPanel({ data, scannedAt }) {
  const [copied, setCopied] = useState(false);
  const cc = data.abuseipdb?.hosting_country;
  const ip = data.resolved_ip && data.resolved_ip !== "N/A" ? data.resolved_ip : null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(ip);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard blocked */
    }
  };
  const rows = [
    ["Indicator", <span className="nb-code">{data.search_query}</span>],
    ["Type", data.search_type],
    [
      "Hosting IP",
      ip ? (
        <span className="nb-ip">
          <span className="nb-code">{ip}</span>
          <button type="button" className="nb-mini" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
        </span>
      ) : (
        "Not resolved"
      ),
    ],
    ["Provider", data.virustotal?.network_provider || "Unknown"],
    [
      "Country",
      <span className="nb-country"><Flag code={cc} />{cc ? countryName(cc) : "Unknown"}</span>,
    ],
    ["Checked at", <span className="nb-code">{timeUTC(scannedAt)}</span>],
  ];
  return (
    <Panel title="Target profile" className="nb-span-4">
      <dl className="nb-kv">
        {rows.map(([k, v]) => (
          <div key={k} className="nb-kv__row">
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}

function VirusTotalPanel({ vt }) {
  const mal = vt?.malicious_flags ?? 0;
  const harm = vt?.harmless_flags ?? 0;
  const total = mal + harm;
  const malPct = total ? (mal / total) * 100 : 0;
  const cells = [
    ...Array.from({ length: mal }, () => "critical"),
    ...Array.from({ length: harm }, () => "good"),
  ];
  return (
    <Panel title="Engine verdicts" source="VirusTotal" className="nb-span-8">
      {vt?.error ? (
        <p className="nb-note">{vt.error}</p>
      ) : (
        <>
          <p className="nb-ratio">
            <span className="nb-ratio__big">{mal}</span>
            <span className="nb-ratio__of">of {total} engines say malicious</span>
          </p>
          <div className="nb-bar" role="img" aria-label={`${mal} malicious, ${harm} harmless`}>
            {mal > 0 && <span className="nb-bar__seg nb-bar__seg--critical" style={{ width: `${Math.max(malPct, 2)}%` }} />}
            {harm > 0 && <span className="nb-bar__seg nb-bar__seg--good" style={{ flex: 1 }} />}
            {total === 0 && <span className="nb-bar__empty">No engine results</span>}
          </div>
          {cells.length > 0 && (
            <div className="nb-engines" aria-hidden="true">
              {cells.map((c, i) => (
                <span key={i} className={`nb-engine nb-engine--${c}`} title={`Engine ${i + 1}: ${c === "critical" ? "Malicious" : "Harmless"}`} />
              ))}
            </div>
          )}
          <p className="nb-legend">
            <span><i className="nb-dot nb-dot--critical" /> Malicious {mal}</span>
            <span><i className="nb-dot nb-dot--good" /> Harmless {harm}</span>
          </p>
        </>
      )}
    </Panel>
  );
}

function AbusePanel({ abuse }) {
  const conf = Math.min(Math.max(abuse?.confidence_score ?? 0, 0), 100);
  const reports = abuse?.total_reports ?? 0;
  const note = abuse?.error || abuse?.notice;
  return (
    <Panel title="Abuse confidence" source="AbuseIPDB" className="nb-span-6">
      {note ? (
        <p className="nb-note">{note}</p>
      ) : (
        <>
          <p className="nb-ratio">
            <span className="nb-ratio__big">{conf}%</span>
            <span className="nb-ratio__of">likely to be abusive, from {reports.toLocaleString()} report{reports === 1 ? "" : "s"}</span>
          </p>
          <div className="nb-meter" role="img" aria-label={`Abuse confidence ${conf} percent`}>
            <span className="nb-meter__zone nb-meter__zone--good" style={{ width: "25%" }}>Low</span>
            <span className="nb-meter__zone nb-meter__zone--warning" style={{ width: "50%" }}>Medium</span>
            <span className="nb-meter__zone nb-meter__zone--critical" style={{ width: "25%" }}>High</span>
            <span className="nb-meter__pin" style={{ left: `${conf}%` }} />
          </div>
          <div className="nb-meter__scale">{[0, 25, 75, 100].map((n) => <span key={n} style={{ left: `${n}%` }}>{n}</span>)}</div>
        </>
      )}
    </Panel>
  );
}

function SignalsPanel({ data }) {
  const mal = data.virustotal?.malicious_flags ?? 0;
  const conf = data.abuseipdb?.confidence_score ?? 0;
  const reports = data.abuseipdb?.total_reports ?? 0;
  const ip = data.resolved_ip && data.resolved_ip !== "N/A" ? data.resolved_ip : null;
  const signals = [
    {
      level: mal >= 5 ? "critical" : mal > 0 ? "warning" : "good",
      text: mal > 0 ? `${mal} VirusTotal engine${mal === 1 ? "" : "s"} report this as malicious.` : "No VirusTotal engine reports this as malicious.",
    },
    {
      level: levelFor(conf),
      text: conf > 0 ? `AbuseIPDB rates the hosting IP ${conf}% likely to be abusive.` : "AbuseIPDB has no abuse confidence against the hosting IP.",
    },
    {
      level: reports > 0 ? "warning" : "good",
      text: reports > 0 ? `${reports.toLocaleString()} abuse report${reports === 1 ? "" : "s"} filed against this IP.` : "No abuse reports on record for this IP.",
    },
    {
      level: ip ? "info" : "warning",
      text: ip
        ? `Hosted on ${ip}${data.virustotal?.network_provider ? `, ${data.virustotal.network_provider.replace(/\.$/, "")}` : ""}.`
        : "The hosting IP could not be resolved.",
    },
  ];
  return (
    <Panel title="Why this verdict" className="nb-span-6">
      <ul className="nb-signals">
        {signals.map((s, i) => (
          <li key={i}>
            <Mark level={s.level} size={22} />
            <span>{s.text}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function HistoryPanel({ history, onPick, loading }) {
  if (history.length < 2) return null;
  return (
    <Panel title="Earlier this session" className="nb-span-12">
      <ul className="nb-history">
        {history.map((h) => (
          <li key={h.query}>
            <button type="button" onClick={() => onPick(h.query)} disabled={loading} className={`nb-hist nb-hist--${h.level}`}>
              <span className="nb-code">{h.query}</span>
              <span className="nb-hist__score">{h.score}</span>
              <span className="nb-hist__time">{h.time}</span>
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function RawJson({ data }) {
  return (
    <details className="nb-card nb-raw nb-span-12">
      <summary>Raw API response</summary>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </details>
  );
}

function LoadingView({ query }) {
  return (
    <section className="nb-loading" aria-live="polite">
      <p>
        Checking <span className="nb-code">{query}</span> with VirusTotal and AbuseIPDB
      </p>
      <div className="nb-loading__bar"><span /></div>
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
    <div className="nb-app">
      <style>{STYLES}</style>
      <TopBar />
      <Ticker history={history} />
      <Hero onSearch={runSearch} loading={loading} full={!loading && !data && !error} />

      {error && (
        <div className="nb-wrap">
          <div className="nb-error" role="alert">
            <Mark level="critical" size={26} />
            <span><strong>Lookup failed.</strong> {error}</span>
          </div>
        </div>
      )}

      {loading && <LoadingView query={pending} />}

      {!loading && data && (
        <>
          <VerdictBand threat={threat} data={data} />
          <div className="nb-wrap">
            <Tiles data={data} />
            <div className="nb-grid">
              <VirusTotalPanel vt={data.virustotal} />
              <TargetPanel data={data} scannedAt={scannedAt} />
              <AbusePanel abuse={data.abuseipdb} />
              <SignalsPanel data={data} />
              <HistoryPanel history={history} onPick={runSearch} loading={loading} />
              <RawJson data={data} />
            </div>
          </div>
        </>
      )}

      <footer className="nb-foot">
        <span>CTI Console</span>
        <span>Data from VirusTotal and AbuseIPDB</span>
      </footer>
    </div>
  );
}

/* ----------------------------- styles ---------------------------- */
const STYLES = `
@import url('https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,500;12..96,700;12..96,800&family=JetBrains+Mono:wght@500;700&display=swap');

.nb-app {
  --ink: #000;
  --paper: #f6f1e6;
  --concrete: #e6decf;
  --good: #5ce1a0;
  --warning: #ffb547;
  --critical: #ff5a5f;
  --info: #e6decf;
  --line: 3px solid var(--ink);
  --pop: 6px 6px 0 var(--ink);
  --pop-sm: 4px 4px 0 var(--ink);
  --gut: clamp(16px, 4vw, 56px);
  --display: "Bricolage Grotesque", system-ui, sans-serif;
  --mono: "JetBrains Mono", ui-monospace, monospace;

  min-height: 100svh;
  display: flex;
  flex-direction: column;
  background: var(--paper);
  color: var(--ink);
  font-family: var(--display);
  font-size: 17px;
  line-height: 1.5;
  text-align: left;
}
.nb-app h1, .nb-app h2, .nb-app h3, .nb-app p { margin: 0; color: var(--ink); }
.nb-app button { font-family: inherit; color: var(--ink); cursor: pointer; }
.nb-app button:disabled { cursor: not-allowed; }
.nb-app :focus-visible { outline: 3px solid var(--ink); outline-offset: 3px; }
.nb-sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
.nb-code { font-family: var(--mono); font-weight: 500; font-size: 0.92em; word-break: break-all; }
.nb-wrap { padding: 0 var(--gut); }

/* top bar */
.nb-top {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 14px var(--gut); border-bottom: var(--line); background: var(--paper);
}
.nb-brand { display: flex; align-items: center; gap: 12px; }
.nb-brand__mark {
  width: 42px; height: 42px; display: grid; place-items: center;
  background: var(--ink); color: var(--paper); border: var(--line); box-shadow: 4px 4px 0 var(--concrete); border-radius: 10px;
}
.nb-brand__name { font-weight: 800; font-size: 22px; letter-spacing: -0.02em; }
.nb-clock { font-family: var(--mono); font-weight: 700; font-size: 14px; border: var(--line); padding: 6px 10px; border-radius: 8px; }

/* ticker */
.nb-ticker { background: var(--concrete); color: var(--ink); overflow: hidden; border-bottom: var(--line); }
.nb-ticker__track { display: flex; width: max-content; animation: nb-scroll 60s linear infinite; }
.nb-ticker__item { display: inline-flex; align-items: center; gap: 10px; padding: 12px 22px; font-weight: 700; font-size: 16px; white-space: nowrap; }
.nb-ticker__star { color: var(--ink); }
@keyframes nb-scroll { to { transform: translateX(-50%); } }
@media (prefers-reduced-motion: reduce) { .nb-ticker__track { animation: none; } }

/* hero */
.nb-hero {
  background: var(--ink); border-bottom: var(--line);
  padding: clamp(40px, 6vw, 80px) var(--gut) clamp(36px, 5vw, 56px);
}
.nb-hero--full {
  flex: 1; display: flex; flex-direction: column; justify-content: center; border-bottom: 0;
}
.nb-app .nb-hero__title { color: var(--paper); }
.nb-hero--full .nb-search { margin-top: 44px; }
.nb-hero__title {
  font-weight: 800; font-size: clamp(44px, 8vw, 112px); line-height: 0.92; letter-spacing: -0.045em;
  max-width: 12ch;
}

.nb-search {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  margin-top: 32px; max-width: 960px; background: var(--paper);
  border: var(--line); border-radius: 14px; box-shadow: var(--pop); padding: 8px 8px 8px 20px;
}
.nb-search { box-shadow: 6px 6px 0 var(--concrete) !important; }
.nb-search.is-invalid { box-shadow: 6px 6px 0 var(--critical) !important; }
.nb-search input {
  flex: 1 1 220px; min-width: 0; border: 0; outline: 0; background: transparent;
  font-family: var(--mono); font-weight: 500; font-size: clamp(18px, 2vw, 24px); padding: 12px 0; color: var(--ink);
}
.nb-search input:focus-visible { outline: none; }
.nb-search:focus-within { outline: 3px solid var(--paper); outline-offset: 5px; }
.nb-search input::placeholder { color: #8a8a8a; }
.nb-search__type { font-weight: 700; font-size: 14px; background: var(--concrete); border: 2px solid var(--ink); border-radius: 999px; padding: 4px 12px; white-space: nowrap; }
.nb-search__type.is-invalid { background: var(--critical); }
.nb-btn {
  font-weight: 800; font-size: 18px; background: var(--ink); color: var(--paper) !important;
  border: var(--line); border-radius: 10px; padding: 14px 26px;
  transition: transform .08s, box-shadow .08s;
}
.nb-btn:hover:not(:disabled) { transform: translate(-2px, -2px); box-shadow: 4px 4px 0 var(--concrete); }
.nb-btn:active:not(:disabled) { transform: translate(0, 0); box-shadow: none; }
.nb-btn:disabled { opacity: .45; }

.nb-try { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-top: 22px; font-weight: 700; color: var(--paper); }
.nb-chip {
  font-family: var(--mono) !important; font-weight: 500; font-size: 15px; background: var(--paper);
  border: 2px solid var(--ink); border-radius: 8px; padding: 6px 12px; box-shadow: 3px 3px 0 var(--concrete);
  transition: transform .08s, box-shadow .08s;
}
.nb-chip:hover:not(:disabled) { transform: translate(-1px, -1px); box-shadow: 4px 4px 0 var(--concrete); }
.nb-chip:active:not(:disabled) { transform: translate(3px, 3px); box-shadow: none; }

/* shared card */
.nb-card { background: var(--paper); border: var(--line); border-radius: 14px; box-shadow: var(--pop); }

/* error + loading */
.nb-error {
  display: flex; align-items: center; gap: 14px; margin-top: 32px;
  background: var(--critical); border: var(--line); border-radius: 14px; box-shadow: var(--pop); padding: 18px 22px; font-size: 18px;
}
.nb-loading { padding: 40px var(--gut); border-bottom: var(--line); }
.nb-loading p { font-weight: 700; font-size: 20px; }
.nb-loading__bar { margin-top: 18px; height: 28px; border: var(--line); border-radius: 8px; overflow: hidden; background: var(--paper); }
.nb-loading__bar span {
  display: block; height: 100%; width: 40%; background: repeating-linear-gradient(-45deg, var(--ink) 0 10px, var(--concrete) 10px 20px);
  animation: nb-load 1.1s ease-in-out infinite alternate;
}
@keyframes nb-load { from { transform: translateX(-10%); } to { transform: translateX(160%); } }
@media (prefers-reduced-motion: reduce) { .nb-loading__bar span { animation: none; width: 100%; } }

/* verdict band */
.nb-verdict { border-bottom: var(--line); padding: clamp(32px, 5vw, 64px) var(--gut); }
.nb-verdict--good { background: var(--good); }
.nb-verdict--warning { background: var(--warning); }
.nb-verdict--critical { background: var(--critical); }
.nb-verdict__inner { display: flex; align-items: center; justify-content: space-between; gap: 32px; flex-wrap: wrap; }
.nb-verdict__main { flex: 1 1 420px; min-width: 0; }
.nb-verdict__query { font-family: var(--mono); font-weight: 700; font-size: clamp(16px, 1.8vw, 22px); word-break: break-all; }
.nb-verdict__word {
  font-weight: 800; font-size: clamp(64px, 14vw, 200px); line-height: 0.95; letter-spacing: -0.055em;
  margin: 6px 0 28px !important;
}
.nb-verdict__summary { font-size: clamp(17px, 1.6vw, 21px); max-width: 52ch; }
.nb-stamp {
  flex: 0 0 auto; display: flex; flex-direction: column; align-items: center; justify-content: center;
  width: clamp(160px, 18vw, 220px); aspect-ratio: 1; background: var(--paper);
  border: 4px solid var(--ink); border-radius: 50%; box-shadow: 8px 8px 0 var(--ink); transform: rotate(-8deg);
}
.nb-stamp__num { font-weight: 800; font-size: clamp(56px, 7vw, 88px); line-height: 1; letter-spacing: -0.04em; }
.nb-stamp__of { font-weight: 700; font-size: 14px; text-align: center; padding: 0 16px; }

/* tiles */
.nb-tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 20px; margin-top: 36px; }
.nb-tile { padding: 18px 20px; display: flex; flex-direction: column; gap: 4px; }
.nb-tile__top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.nb-tile__label { font-weight: 700; font-size: 15px; }
.nb-tile__value { font-weight: 800; font-size: clamp(40px, 4vw, 56px); line-height: 1.05; letter-spacing: -0.03em; }
.nb-tile__note { font-size: 14px; }

.nb-mark {
  flex: 0 0 auto; display: inline-grid; place-items: center; border: 2px solid var(--ink); border-radius: 50%;
  font-weight: 800; line-height: 1;
}
.nb-mark--good { background: var(--good); }
.nb-mark--warning { background: var(--warning); }
.nb-mark--critical { background: var(--critical); }
.nb-mark--info { background: var(--info); }

/* panels grid */
.nb-grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 20px; margin: 20px 0 56px; }
.nb-span-4 { grid-column: span 4; }
.nb-span-6 { grid-column: span 6; }
.nb-span-8 { grid-column: span 8; }
.nb-span-12 { grid-column: span 12; }
@media (max-width: 960px) { .nb-span-4, .nb-span-6, .nb-span-8 { grid-column: span 12; } }

.nb-panel { display: flex; flex-direction: column; overflow: hidden; }
.nb-panel__head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 20px; border-bottom: var(--line); }
.nb-panel__head h3 { font-weight: 800; font-size: 20px; letter-spacing: -0.01em; }
.nb-tag { font-weight: 700; font-size: 13px; background: var(--concrete); border: 2px solid var(--ink); border-radius: 999px; padding: 2px 10px; }
.nb-panel__body { padding: 20px; flex: 1; }
.nb-note { font-weight: 500; }

.nb-ratio { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.nb-ratio__big { font-weight: 800; font-size: 56px; line-height: 1; letter-spacing: -0.03em; }
.nb-ratio__of { font-weight: 500; }

.nb-bar { display: flex; height: 34px; margin-top: 18px; border: var(--line); border-radius: 8px; overflow: hidden; background: var(--paper); }
.nb-bar__seg + .nb-bar__seg { border-left: var(--line); }
.nb-bar__seg--critical { background: var(--critical); }
.nb-bar__seg--good { background: var(--good); }
.nb-bar__empty { margin: auto; font-weight: 700; font-size: 14px; }

.nb-engines { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 16px; }
.nb-engine { width: 16px; height: 16px; border: 2px solid var(--ink); border-radius: 3px; }
.nb-engine--critical { background: var(--critical); }
.nb-engine--good { background: var(--good); }

.nb-legend { display: flex; gap: 20px; flex-wrap: wrap; margin-top: 16px !important; font-weight: 700; font-size: 15px; }
.nb-legend span { display: inline-flex; align-items: center; gap: 8px; }
.nb-dot { display: inline-block; width: 12px; height: 12px; border: 2px solid currentColor; border-radius: 50%; }
.nb-dot--good { background: var(--good); }
.nb-dot--warning { background: var(--warning); }
.nb-dot--critical { background: var(--critical); }
.nb-dot--info { background: var(--info); }

.nb-meter { position: relative; display: flex; height: 40px; margin-top: 22px; border: var(--line); border-radius: 8px; }
.nb-meter__zone { display: grid; place-items: center; font-weight: 700; font-size: 13px; }
.nb-meter__zone + .nb-meter__zone { border-left: var(--line); }
.nb-meter__zone--good { background: var(--good); border-radius: 5px 0 0 5px; }
.nb-meter__zone--warning { background: var(--warning); }
.nb-meter__zone--critical { background: var(--critical); border-radius: 0 5px 5px 0; }
.nb-meter__pin {
  position: absolute; top: -12px; bottom: -12px; width: 8px; margin-left: -4px;
  background: var(--ink); border: 2px solid var(--paper); border-radius: 4px;
}
.nb-meter__scale { position: relative; height: 18px; margin-top: 14px; font-family: var(--mono); font-size: 13px; }
.nb-meter__scale span { position: absolute; transform: translateX(-50%); }
.nb-meter__scale span:first-child { transform: none; }
.nb-meter__scale span:last-child { transform: translateX(-100%); }

.nb-kv { margin: 0; display: flex; flex-direction: column; }
.nb-kv__row { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 10px 0; border-bottom: 2px dashed var(--ink); }
.nb-kv__row:last-child { border-bottom: 0; }
.nb-kv dt { font-weight: 700; font-size: 15px; flex: 0 0 auto; }
.nb-kv dd { margin: 0; text-align: right; font-weight: 500; min-width: 0; }
.nb-ip, .nb-country { display: inline-flex; align-items: center; gap: 8px; }
.nb-mini { font-weight: 700; font-size: 12px; background: var(--concrete); border: 2px solid var(--ink); border-radius: 6px; padding: 2px 8px; }
.nb-flag { border: 2px solid var(--ink); border-radius: 3px; object-fit: cover; }
.nb-flag--text { font-family: var(--mono); font-size: 12px; padding: 0 4px; }

.nb-signals { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 14px; }
.nb-signals li { display: flex; align-items: flex-start; gap: 12px; font-weight: 500; }

.nb-history { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 12px; }
.nb-hist {
  display: flex; align-items: center; gap: 12px; border: 2px solid var(--ink); border-radius: 10px;
  padding: 8px 12px; box-shadow: 3px 3px 0 var(--ink); transition: transform .08s, box-shadow .08s;
}
.nb-hist--good { background: var(--good); }
.nb-hist--warning { background: var(--warning); }
.nb-hist--critical { background: var(--critical); }
.nb-hist:hover:not(:disabled) { transform: translate(-1px, -1px); box-shadow: 4px 4px 0 var(--ink); }
.nb-hist__score { font-weight: 800; }
.nb-hist__time { font-family: var(--mono); font-size: 13px; }

.nb-raw { padding: 0; overflow: hidden; }
.nb-raw summary { cursor: pointer; font-weight: 800; font-size: 18px; padding: 14px 20px; }
.nb-raw[open] summary { border-bottom: var(--line); }
.nb-raw pre { margin: 0; padding: 20px; overflow-x: auto; font-family: var(--mono); font-size: 13px; background: var(--concrete); }

/* footer */
.nb-foot {
  margin-top: auto; display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap;
  background: var(--ink); color: var(--paper); padding: 18px var(--gut); font-weight: 700; font-size: 15px;
}
`;