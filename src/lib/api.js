import { supabase } from './supabase.js';

export async function fetchSessions() {
  const { data, error } = await supabase.from('lab_sessions').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data;
}

export async function createSession(form) {
  const { data, error } = await supabase.from('lab_sessions').insert(form).select().single();
  if (error) throw error;
  return data;
}

export async function updateSessionStatus(id, status, extra = {}) {
  const { error } = await supabase.from('lab_sessions').update({ status, ...extra }).eq('id', id);
  if (error) throw error;
}

export async function deleteSession(id) {
  const { error } = await supabase.from('lab_sessions').delete().eq('id', id);
  if (error) throw error;
}

export async function fetchTechniques() {
  const { data, error } = await supabase.from('techniques').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data;
}

export async function createTechnique(form) {
  const payload = { ...form, session_id: form.session_id || null, target_vm_id: form.target_vm_id || null };
  const { data, error } = await supabase.from('techniques').insert(payload).select().single();
  if (error) throw error;
  return data;
}

export async function deleteTechnique(id) {
  const { error } = await supabase.from('techniques').delete().eq('id', id);
  if (error) throw error;
}

export async function fetchVms() {
  const { data, error } = await supabase.from('lab_vms').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data;
}

export async function createVm(form) {
  const { data, error } = await supabase.from('lab_vms').insert(form).select().single();
  if (error) throw error;
  return data;
}

export async function deleteVm(id) {
  const { error } = await supabase.from('lab_vms').delete().eq('id', id);
  if (error) throw error;
}

export async function fetchCredentials() {
  const { data, error } = await supabase.from('credentials').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data;
}

export async function createCredential(form) {
  const payload = { ...form, target_vm_id: form.target_vm_id || null, session_id: form.session_id || null };
  const { data, error } = await supabase.from('credentials').insert(payload).select().single();
  if (error) throw error;
  return data;
}

export async function deleteCredential(id) {
  const { error } = await supabase.from('credentials').delete().eq('id', id);
  if (error) throw error;
}

export async function fetchProgress() {
  const { data, error } = await supabase.from('progress').select('*').order('category');
  if (error) throw error;
  return data;
}

export async function fetchLoot() {
  const { data, error } = await supabase.from('sliver_loot').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data;
}

export async function saveLoot(entry) {
  const { data: { user } } = await supabase.auth.getUser();
  const { data, error } = await supabase
    .from('sliver_loot')
    .insert({ ...entry, user_id: user.id })
    .select()
    .single();
  if (error) throw error;
  return data;
}

export async function deleteLoot(id) {
  const { error } = await supabase.from('sliver_loot').delete().eq('id', id);
  if (error) throw error;
}

// ── Terminal History ──────────────────────────────────────────────────────
export async function fetchTerminalHistory(targetId) {
  const { data, error } = await supabase
    .from('terminal_history')
    .select('*')
    .eq('target_id', targetId)
    .order('created_at', { ascending: true })
    .limit(500);
  if (error) throw error;
  return data;
}

export async function saveTerminalEntry(entry) {
  const { data: { user } } = await supabase.auth.getUser();
  const { error } = await supabase
    .from('terminal_history')
    .insert({ ...entry, user_id: user.id });
  if (error) throw error;
}

export async function clearTerminalHistory(targetId) {
  const { error } = await supabase
    .from('terminal_history')
    .delete()
    .eq('target_id', targetId);
  if (error) throw error;
}

// ── Kill Chain Checklist ─────────────────────────────────────────────────
export async function fetchKillchain(sessionId) {
  const { data, error } = await supabase
    .from('killchain_checks')
    .select('*')
    .eq('session_id', sessionId)
    .order('tactic');
  if (error) throw error;
  return data;
}

export async function upsertKillchain(sessionId, tactic, checked, notes = '') {
  const { data: { user } } = await supabase.auth.getUser();
  const { data, error } = await supabase
    .from('killchain_checks')
    .upsert(
      { session_id: sessionId, tactic, checked, notes, user_id: user.id, updated_at: new Date().toISOString() },
      { onConflict: 'session_id,tactic' }
    )
    .select()
    .single();
  if (error) throw error;
  return data;
}

// ── Scan Results ─────────────────────────────────────────────────────────
export async function fetchScanHistory(host) {
  const query = supabase.from('scan_results').select('*').order('created_at', { ascending: false }).limit(50);
  if (host) query.eq('host', host);
  const { data, error } = await query;
  if (error) throw error;
  return data;
}

export async function fetchAllScans() {
  const { data, error } = await supabase.from('scan_results').select('*').order('created_at', { ascending: false }).limit(100);
  if (error) throw error;
  return data;
}

export async function saveScanResult(entry) {
  const { data: { user } } = await supabase.auth.getUser();
  const { data, error } = await supabase
    .from('scan_results')
    .insert({ ...entry, user_id: user.id })
    .select()
    .single();
  if (error) throw error;
  return data;
}

export async function deleteScanResult(id) {
  const { error } = await supabase.from('scan_results').delete().eq('id', id);
  if (error) throw error;
}

// ── IOC Tracker ─────────────────────────────────────────────────────────
export async function fetchIocs() {
  const { data, error } = await supabase.from('iocs').select('*').order('created_at', { ascending: false }).limit(200);
  if (error) throw error;
  return data;
}

export async function createIoc(entry) {
  const { data: { user } } = await supabase.auth.getUser();
  const { data, error } = await supabase.from('iocs').insert({ ...entry, user_id: user.id }).select().single();
  if (error) throw error;
  return data;
}

export async function deleteIoc(id) {
  const { error } = await supabase.from('iocs').delete().eq('id', id);
  if (error) throw error;
}

export async function upsertProgress(category, techniquesStudied) {
  const { data, error } = await supabase
    .from('progress')
    .upsert({ category, techniques_studied: techniquesStudied, last_updated: new Date().toISOString() }, { onConflict: 'category' })
    .select()
    .single();
  if (error) throw error;
  return data;
}
