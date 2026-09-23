import { useCallback, useEffect, useState } from "react";

// Runtime config — fetched from Worker; refreshed automatically on fetch failure
let _configCache = null;
let _configCallbacks = [];

async function fetchConfig(force = false) {
  if (_configCache && !force) return _configCache;
  const devUrl = import.meta.env.VITE_SLIVER_BRIDGE_URL;
  const devKey = import.meta.env.VITE_SLIVER_BRIDGE_API_KEY;
  try {
    const res = await fetch("/api/config");
    if (res.ok) {
      const data = await res.json();
      if (data.bridgeUrl) {
        _configCache = { url: data.bridgeUrl, key: data.bridgeKey };
        _configCallbacks.forEach(cb => cb(_configCache));
        return _configCache;
      }
    }
  } catch { /* ignore */ }
  _configCache = { url: devUrl || "", key: devKey || "" };
  return _configCache;
}

async function bridgeFetch(path, options = {}) {
  let cfg = await fetchConfig();
  const doFetch = async (c) => {
    const res = await fetch(`${c.url}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-Bridge-Api-Key": c.key || "",
        ...options.headers,
      },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`Bridge respondeu ${res.status}${body ? `: ${body}` : ""}`);
    }
    return res.json();
  };
  try {
    return await doFetch(cfg);
  } catch (err) {
    // On network failure, refresh config and retry once (tunnel URL may have changed)
    if (err instanceof TypeError) {
      _configCache = null;
      cfg = await fetchConfig(true);
      return doFetch(cfg);
    }
    throw err;
  }
}

export function useSliver() {
  const [bridgeUrl, setBridgeUrl] = useState(import.meta.env.VITE_SLIVER_BRIDGE_URL ?? "");
  const [bridgeKey, setBridgeKey] = useState(import.meta.env.VITE_SLIVER_BRIDGE_API_KEY ?? "");
  const [status, setStatus] = useState("disconnected");
  const [sessions, setSessions] = useState([]);
  const [error, setError] = useState(null);

  const enabled = Boolean(bridgeUrl || import.meta.env.PROD);

  useEffect(() => {
    // Initial fetch
    fetchConfig().then(cfg => { setBridgeUrl(cfg.url); setBridgeKey(cfg.key); });
    // Subscribe to config refreshes (triggered on tunnel URL change)
    const cb = (cfg) => { setBridgeUrl(cfg.url); setBridgeKey(cfg.key); };
    _configCallbacks.push(cb);
    return () => { _configCallbacks = _configCallbacks.filter(f => f !== cb); };
  }, []);

  const refresh = useCallback(async () => {
    if (!enabled) return;
    setStatus("checking");
    try {
      const [sessionsData, beaconsData] = await Promise.allSettled([
        bridgeFetch("/sessions"),
        bridgeFetch("/beacons"),
      ]);
      const s = sessionsData.status === "fulfilled" ? (sessionsData.value.sessions || []) : [];
      const b = beaconsData.status === "fulfilled"
        ? (beaconsData.value.beacons || []).map(x => ({ ...x, _type: "beacon" }))
        : [];
      setSessions([...s, ...b]);
      setStatus("connected");
      setError(null);
    } catch (err) {
      setStatus("error");
      setError(err.message);
    }
  }, [enabled]);

  // Execute command — fire-and-forget for sessions, returns task_id for beacons
  const runTask = useCallback((id, exe, args, isBeacon = false) => {
    const path = isBeacon ? `/beacons/${id}/task` : `/sessions/${id}/task`;
    return bridgeFetch(path, { method: "POST", body: JSON.stringify({ exe, args }) });
  }, []);

  // Queue any beacon action (screenshot, ls, ps, netstat, execute, download, upload)
  const beaconAction = useCallback((id, action, opts = {}) => {
    return bridgeFetch(`/beacons/${id}/action`, {
      method: "POST",
      body: JSON.stringify({
        action,
        path: opts.path ?? ".",
        exe: opts.exe ?? "",
        args: opts.args ?? [],
        data: opts.data ?? "",
      }),
    });
  }, []);

  // Poll once for a queued beacon task result
  const getBeaconResult = useCallback((id, taskId) => {
    return bridgeFetch(`/beacons/${id}/result/${taskId}`);
  }, []);

  // Kill a beacon
  const killBeacon = useCallback((id) => {
    return bridgeFetch(`/beacons/${id}`, { method: "DELETE" });
  }, []);

  // Listeners
  const listListeners = useCallback(() => bridgeFetch("/listeners"), []);

  const createListener = useCallback((config) =>
    bridgeFetch("/listeners", { method: "POST", body: JSON.stringify(config) }), []);

  const stopListener = useCallback((jobId) =>
    bridgeFetch(`/listeners/${jobId}`, { method: "DELETE" }), []);

  // Implant generation
  const generateImplant = useCallback((config) =>
    bridgeFetch("/implants/generate", { method: "POST", body: JSON.stringify(config) }), []);

  // Network scan
  const runScan = useCallback((targets, ports = [], profile = "default", timeout = 3.0) =>
    bridgeFetch("/scan", { method: "POST", body: JSON.stringify({ targets, ports, profile, timeout }) }), []);

  useEffect(() => {
    if (enabled) refresh();
  }, [enabled, refresh]);

  return {
    enabled, status, sessions, error,
    refresh, runTask, beaconAction, getBeaconResult, killBeacon,
    listListeners, createListener, stopListener,
    generateImplant, runScan,
    bridgeUrl, bridgeKey,
  };
}
