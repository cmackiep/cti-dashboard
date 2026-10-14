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
  if (/^https?:\/\//i.test(v)) {
    try {
      const host = new URL(v).hostname;
      if (DOMAIN.test(host) || IPV4.test(host)) return "URL";
    } catch {
      /* not a valid URL */
    }
    return "invalid";
  }
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

function levelFor(value, high = 75) {
  if (value >= high) return "critical";
  if (value > 0) return "warning";
  return "good";
}

const timeUTC = (d) => d.toISOString().slice(11, 19) + " UTC";

const LEVEL_WORD = { good: "Clean", warning: "Suspicious", critical: "High risk", info: "Info" };

// ["a", "b", "c"] becomes "a, b and c"
const listJoin = (items) =>
  items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;

/* Each reputation source gives its own 0-100 score.
   The verdict takes the worst one, so one credible alarm is enough to flag it. */
function scoreSources(data) {
  const vt = data?.virustotal;
  const abuse = data?.abuseipdb;
  const otx = data?.otx;
  const sources = [];

  // VirusTotal: 15 points for each engine that says malicious (5+ engines = high risk)
  if (!vt || vt.error) {
    sources.push({ name: "VirusTotal", score: null, headline: "No result", detail: vt?.error || "Lookup skipped." });
  } else {
    const mal = vt.malicious_flags ?? 0;
    const total = mal + (vt.harmless_flags ?? 0);
    sources.push({
      name: "VirusTotal",
      score: Math.min(100, mal * 15),
      headline: `${mal} of ${total} security engines flag it`,
      detail:
        vt.verdict_source === "url"
          ? "From VirusTotal's scan of this exact URL."
          : data.url_note || "Verdicts from antivirus and security vendors.",
    });
  }

  // AbuseIPDB: its own confidence score, built from abuse reports by other networks
  if (!abuse || abuse.error || abuse.notice) {
    sources.push({ name: "AbuseIPDB", score: null, headline: "No result", detail: abuse?.error || abuse?.notice || "Lookup skipped." });
  } else {
    const conf = abuse.confidence_score ?? 0;
    const reports = abuse.total_reports ?? 0;
    const count = `${reports.toLocaleString()} report${reports === 1 ? "" : "s"} in the last 90 days`;
    sources.push({
      name: "AbuseIPDB",
      score: conf,
      headline: `${conf}% abuse confidence`,
      detail: reports > 0 && conf === 0 ? `${count}, but AbuseIPDB weighs them at 0%.` : `${count}.`,
    });
  }

  // AlienVault OTX: community threat reports ("pulses"). Known-good indicators score 0.
  if (!otx || otx.error || otx.notice) {
    sources.push({ name: "AlienVault OTX", score: null, headline: "No result", detail: otx?.error || otx?.notice || "Lookup skipped." });
  } else {
    const pulses = otx.pulse_count ?? 0;
    const families = otx.malware_families ?? [];
    const knownGood = otx.known_good ?? [];
    let score = 0;
    if (knownGood.length === 0 && families.length > 0) score = 50;
    else if (knownGood.length === 0 && pulses > 0) score = 25;
    sources.push({
      name: "AlienVault OTX",
      score,
      headline:
        knownGood.length > 0
          ? "Listed as known good"
          : `In ${pulses} community threat report${pulses === 1 ? "" : "s"}`,
      detail:
        knownGood.length > 0
          ? knownGood.join(" · ")
          : families.length > 0
          ? `Linked to ${families.join(", ")}.`
          : pulses > 0
          ? `Latest: ${otx.recent_pulses?.[0]}`
          : "No community reports mention it.",
    });
  }

  return sources.map((s) => ({ ...s, level: s.score === null ? "info" : levelFor(s.score) }));
}

function assessThreat(data) {
  const sources = scoreSources(data);
  const score = Math.max(0, ...sources.map((s) => s.score ?? 0));
  const level = levelFor(score);
  return { level, label: LEVEL_WORD[level], score, sources };
}

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
          placeholder="Paste an IP address, domain or URL to check it"
          spellCheck="false"
          autoComplete="off"
        />
        {type && (
          <span className={`nb-search__type ${type === "invalid" ? "is-invalid" : ""}`}>
            {type === "invalid" ? "Not an IP, domain or URL" : type}
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
  const flagged = threat.sources.filter((s) => s.score > 0).map((s) => s.name);
  const checked = threat.sources.filter((s) => s.score !== null).length;
  const provider = data.virustotal?.network_provider?.replace(/\.$/, "");
  const cc = data.abuseipdb?.hosting_country;
  const where = provider ? ` Hosted by ${provider}${cc ? ` in ${countryName(cc)}` : ""}.` : "";
  const summary =
    (flagged.length > 0
      ? `Flagged by ${listJoin(flagged)}.`
      : `None of the ${checked} reputation sources flag it.`) + where;
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
  const hostnames = data.shodan?.hostnames ?? [];
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
    ...(data.search_type === "URL" ? [["Domain", <span className="nb-code">{data.domain}</span>]] : []),
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
    ...(hostnames.length ? [["Hostnames", <span className="nb-code">{hostnames.slice(0, 3).join(", ")}</span>]] : []),
    ["Provider", data.virustotal?.network_provider || "Unknown"],
    [
      "Country",
      <span className="nb-country"><Flag code={cc} />{cc ? countryName(cc) : "Unknown"}</span>,
    ],
    ["Checked at", <span className="nb-code">{timeUTC(scannedAt)}</span>],
  ];
  return (
    <Panel title="What is it?" className="nb-span-5">
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

function ReputationPanel({ sources }) {
  return (
    <Panel title="Is it known to be bad?" className="nb-span-7">
      <p className="nb-lede">Each source scores it out of 100. The most worried one wins. Better a false alarm than a missed baddie.</p>
      <ul className="nb-rep">
        {sources.map((s) => (
          <li key={s.name} className="nb-rep__row">
            <Mark level={s.level} size={28} />
            <div className="nb-rep__text">
              <span className="nb-rep__source">{s.name}</span>
              <strong className="nb-rep__headline">{s.headline}</strong>
              <span className="nb-rep__detail">{s.detail}</span>
            </div>
            <span className={`nb-rep__score nb-rep__score--${s.level}`}>
              {s.score ?? "N/A"}
              {s.score !== null && <small>/100</small>}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Chips({ label, items, max = 12 }) {
  if (items.length === 0) return null;
  const extra = items.length - max;
  return (
    <div className="nb-chips">
      <strong>{label}</strong>
      {items.slice(0, max).map((item) => (
        <span key={item} className="nb-tag">{item}</span>
      ))}
      {extra > 0 && <span>+{extra} more</span>}
    </div>
  );
}

function ShodanPanel({ shodan }) {
  const note = shodan?.error || shodan?.notice;
  const ports = shodan?.open_ports ?? [];
  const vulns = shodan?.vulns ?? [];
  const tags = shodan?.tags ?? [];
  return (
    <Panel title="How exposed is it?" source="Shodan" className="nb-span-12">
      {note ? (
        <p className="nb-note">{note}</p>
      ) : (
        <>
          <div className="nb-exposure">
          <p className="nb-ratio">
            <span className="nb-ratio__big">{ports.length}</span>
            <span className="nb-ratio__of">
              open port{ports.length === 1 ? "" : "s"}, {vulns.length} known vulnerabilit{vulns.length === 1 ? "y" : "ies"}
            </span>
          </p>
          <div>
            <Chips label="Ports" items={ports} />
            <Chips label="Vulnerabilities" items={vulns} />
            <Chips label="Tags" items={tags} />
          </div>
          </div>
          <p className="nb-vt-note">
            Open ports and known flaws show what an attacker could reach. They don't make it malicious, so they don't change the score.
          </p>
        </>
      )}
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
  const [copied, setCopied] = useState(false);
  const json = JSON.stringify(data, null, 2);
  const copy = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(json);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard blocked */
    }
  };
  return (
    <details className="nb-card nb-raw nb-span-12">
      <summary>
        Report data (JSON)
        <button type="button" className="nb-mini" onClick={copy}>
          {copied ? "Copied" : "Copy JSON"}
        </button>
      </summary>
      <pre>{json}</pre>
    </details>
  );
}
function LoadingView({ query }) {
  return (
    <section className="nb-loading" aria-live="polite">
      <p>
        Checking <span className="nb-code">{query}</span> with VirusTotal, AbuseIPDB, AlienVault OTX and Shodan
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
            <div className="nb-grid">
              <TargetPanel data={data} scannedAt={scannedAt} />
              <ReputationPanel sources={threat.sources} />
              <ShodanPanel shodan={data.shodan} />
              <HistoryPanel history={history} onPick={runSearch} loading={loading} />
              <RawJson data={data} />
            </div>
          </div>
        </>
      )}

      <footer className="nb-foot">
        <span>CTI Console</span>
        <span>Data from VirusTotal, AbuseIPDB, AlienVault OTX and Shodan</span>
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

.nb-mark {
  flex: 0 0 auto; display: inline-grid; place-items: center; border: 2px solid var(--ink); border-radius: 50%;
  font-weight: 800; line-height: 1;
}
.nb-mark--good { background: var(--good); }
.nb-mark--warning { background: var(--warning); }
.nb-mark--critical { background: var(--critical); }
.nb-mark--info { background: var(--info); }

/* panels grid */
.nb-grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 20px; margin: 36px 0 56px; }
.nb-span-4 { grid-column: span 4; }
.nb-span-5 { grid-column: span 5; }
.nb-span-6 { grid-column: span 6; }
.nb-span-7 { grid-column: span 7; }
.nb-span-8 { grid-column: span 8; }
.nb-span-12 { grid-column: span 12; }
@media (max-width: 960px) { .nb-span-4, .nb-span-5, .nb-span-6, .nb-span-7, .nb-span-8 { grid-column: span 12; } }

.nb-panel { display: flex; flex-direction: column; overflow: hidden; }
.nb-panel__head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 20px; border-bottom: var(--line); }
.nb-panel__head h3 { font-weight: 800; font-size: 20px; letter-spacing: -0.01em; }
.nb-tag { font-weight: 700; font-size: 13px; background: var(--concrete); border: 2px solid var(--ink); border-radius: 999px; padding: 2px 10px; }
.nb-panel__body { padding: 20px; flex: 1; }
.nb-note { font-weight: 500; }
.nb-vt-note { margin-top: 14px !important; padding: 10px 14px; background: var(--concrete); border: 2px solid var(--ink); border-radius: 8px; font-size: 15px; font-weight: 500; }


.nb-kv { margin: 0; display: flex; flex-direction: column; }
.nb-kv__row { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 10px 0; border-bottom: 2px dashed var(--ink); }
.nb-kv__row:last-child { border-bottom: 0; }
.nb-kv dt { font-weight: 700; font-size: 15px; flex: 0 0 auto; }
.nb-kv dd { margin: 0; text-align: right; font-weight: 500; min-width: 0; }
.nb-ip, .nb-country { display: inline-flex; align-items: center; gap: 8px; }
.nb-mini { font-weight: 700; font-size: 12px; background: var(--concrete); border: 2px solid var(--ink); border-radius: 6px; padding: 2px 8px; }
.nb-flag { border: 2px solid var(--ink); border-radius: 3px; object-fit: cover; }
.nb-flag--text { font-family: var(--mono); font-size: 12px; padding: 0 4px; }

.nb-chips { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 14px; }
.nb-ratio { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.nb-ratio__big { font-weight: 800; font-size: 56px; line-height: 1; letter-spacing: -0.03em; }
.nb-ratio__of { font-weight: 500; }

.nb-exposure { display: grid; grid-template-columns: minmax(220px, auto) 1fr; gap: 8px 32px; align-items: start; }
.nb-exposure .nb-chips:first-child { margin-top: 4px; }
@media (max-width: 700px) { .nb-exposure { grid-template-columns: 1fr; } }
.nb-lede { font-weight: 500; margin-bottom: 4px !important; }
.nb-rep { list-style: none; margin: 0; padding: 0; }
.nb-rep__row { display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 18px; padding: 18px 0; border-bottom: 2px dashed var(--ink); }
.nb-rep__row:last-child { border-bottom: 0; padding-bottom: 0; }
.nb-rep__text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.nb-rep__source { font-weight: 700; font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em; }
.nb-rep__headline { font-weight: 800; font-size: clamp(19px, 2vw, 24px); line-height: 1.2; }
.nb-rep__detail { font-size: 15px; overflow-wrap: anywhere; }
.nb-rep__score {
  min-width: 92px; text-align: center; font-weight: 800; font-size: 26px; line-height: 1;
  border: var(--line); border-radius: 10px; padding: 10px 12px; box-shadow: var(--pop-sm);
}
.nb-rep__score small { font-size: 14px; font-weight: 700; }
.nb-rep__score--good { background: var(--good); }
.nb-rep__score--warning { background: var(--warning); }
.nb-rep__score--critical { background: var(--critical); }
.nb-rep__score--info { background: var(--info); font-size: 18px; }
@media (max-width: 560px) { .nb-rep__row { grid-template-columns: auto 1fr; } .nb-rep__score { grid-column: 2; justify-self: start; } }

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
.nb-raw summary .nb-mini { margin-left: 12px; vertical-align: middle; }
/* footer */
.nb-foot {
  margin-top: auto; display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap;
  background: var(--ink); color: var(--paper); padding: 18px var(--gut); font-weight: 700; font-size: 15px;
}
`;