// ── Tab 切換 ────────────────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${name}`));

  // 歷史 Tab 不顯示掃描控制列
  const isHistory = name === 'history';
  document.getElementById('scan-controls').style.display = isHistory ? 'none' : '';
}

// ── 掃描主流程 ─────────────────────────────────────────────────────
async function doScan() {
  const activeTab = document.querySelector('.tab.active').dataset.tab;
  const backend = document.querySelector('input[name="backend"]:checked').value;

  hideError();
  setScanning(true);
  document.getElementById('results').style.display = 'none';
  document.getElementById('filter-bar').style.display = 'none';

  try {
    let data;

    if (activeTab === 'snippet') {
      const code = document.getElementById('snippet-input').value.trim();
      const filename = document.getElementById('snippet-filename').value.trim() || 'code_snippet';
      if (!code) { showError('請輸入程式碼內容'); return; }
      showStatus('正在分析程式碼，請稍候...');
      data = await postJson('/api/scan', { input_type: 'snippet', content: code, filename, backend });

    } else if (activeTab === 'upload') {
      const fileInput = document.getElementById('file-input');
      if (!fileInput.files.length) { showError('請選擇要上傳的檔案'); return; }
      const form = new FormData();
      form.append('file', fileInput.files[0]);
      form.append('backend', backend);
      showStatus('正在分析程式碼，請稍候...');
      data = await postForm('/api/scan/upload', form);

    } else if (activeTab === 'github') {
      const url = document.getElementById('github-url').value.trim();
      if (!url) { showError('請輸入 GitHub Repository URL'); return; }
      showStatus('正在抓取並分析 Repository，請稍候...');
      data = await postJson('/api/scan', { input_type: 'github', url, backend });

    } else if (activeTab === 'directory') {
      const dir = document.getElementById('dir-path').value.trim();
      if (!dir) { showError('請輸入目錄路徑'); return; }
      showStatus('正在提交目錄掃描任務...');
      data = await runDirectoryScan(dir, backend);
    }

    if (data) renderResults(data);

  } catch (err) {
    showError(err.message || '掃描失敗，請確認 API 設定並重試。');
  } finally {
    hideStatus();
    setScanning(false);
    hideDirProgress();
  }
}

// ── 目錄掃描：提交 + 輪詢進度 ────────────────────────────────────────
async function runDirectoryScan(directory, backend) {
  // 提交任務
  const submitRes = await postJson('/api/scan/directory', { directory, backend });
  const scanId = submitRes.scan_id;

  showDirProgress(0, 0);
  showStatus('目錄掃描進行中，請稍候...');

  // 輪詢，每 2 秒查詢一次
  return new Promise((resolve, reject) => {
    const timer = setInterval(async () => {
      try {
        const statusRes = await fetch(`/api/scan/${scanId}/status`);
        if (!statusRes.ok) {
          clearInterval(timer);
          reject(new Error(`狀態查詢失敗: HTTP ${statusRes.status}`));
          return;
        }
        const s = await statusRes.json();

        // 更新進度條
        if (s.files_total > 0) {
          showDirProgress(s.files_done, s.files_total);
        }

        if (s.status === 'completed') {
          clearInterval(timer);
          resolve({
            scan_id: scanId,
            files_scanned: s.files_total,
            total_findings: s.total_findings || 0,
            summary: s.summary || { Critical: 0, High: 0, Medium: 0, Low: 0 },
            findings: s.findings || [],
            report_url: s.report_url,
          });
        } else if (s.status === 'error') {
          clearInterval(timer);
          reject(new Error(s.error || '目錄掃描失敗'));
        }
      } catch (e) {
        clearInterval(timer);
        reject(e);
      }
    }, 2000);
  });
}

function showDirProgress(done, total) {
  const wrap = document.getElementById('dir-progress-wrap');
  wrap.style.display = 'block';
  document.getElementById('dir-files-done').textContent = done;
  document.getElementById('dir-files-total').textContent = total || '?';
  if (total > 0) {
    document.getElementById('dir-progress-bar').style.width = `${Math.round(done / total * 100)}%`;
  }
}

function hideDirProgress() {
  document.getElementById('dir-progress-wrap').style.display = 'none';
}

// ── 掃描歷史 ────────────────────────────────────────────────────────
async function loadHistory() {
  const list = document.getElementById('history-list');
  list.innerHTML = '<p style="color:var(--muted);font-size:0.85rem;">載入中...</p>';
  try {
    const res = await fetch('/api/reports');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const { reports } = await res.json();

    if (!reports.length) {
      list.innerHTML = '<p style="color:var(--muted);font-size:0.85rem;">尚無掃描記錄。</p>';
      return;
    }

    list.innerHTML = '';
    reports.forEach(r => {
      const row = document.createElement('div');
      row.className = 'history-row';
      row.innerHTML = `
        <div class="history-id">${esc(r.scan_id.slice(0, 8))}…</div>
        <div class="history-time">${esc(r.created_at)}</div>
        <a class="history-link" href="${esc(r.report_url)}" target="_blank">📄 查看報告</a>
      `;
      list.appendChild(row);
    });
  } catch (e) {
    list.innerHTML = `<p style="color:var(--critical);font-size:0.85rem;">載入失敗: ${esc(e.message)}</p>`;
  }
}

// ── HTTP 工具 ───────────────────────────────────────────────────────
async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

async function postForm(url, form) {
  const res = await fetch(url, { method: 'POST', body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── 渲染結果 ────────────────────────────────────────────────────────
let _allFindings = [];

function renderResults(data) {
  const { scan_id, total_findings, summary, findings, report_url } = data;
  _allFindings = findings || [];

  // 統計卡
  setText('num-total', total_findings);
  setText('num-critical', summary.Critical);
  setText('num-high', summary.High);
  setText('num-medium', summary.Medium);
  setText('num-low', summary.Low);

  // HTML 報告連結
  const link = document.getElementById('report-link');
  link.href = report_url;
  link.textContent = `📄 查看完整 HTML 報告 (Scan ID: ${scan_id})`;

  // 顯示篩選列
  if (findings.length > 0) {
    document.getElementById('filter-bar').style.display = 'flex';
    resetFilter();
  }

  renderFindingList(_allFindings);

  document.getElementById('results').style.display = 'block';
  document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

function renderFindingList(findings) {
  const list = document.getElementById('findings-list');
  list.innerHTML = '';

  if (!findings.length) {
    list.innerHTML = '<p style="color:var(--low);text-align:center;padding:2rem;">✓ 未發現安全漏洞</p>';
    return;
  }

  findings.forEach((f, i) => {
    const card = buildFindingCard(f, i + 1);
    // 自動展開第一個 Critical 漏洞
    if (i === 0 && f.severity === 'Critical') {
      card.classList.add('open');
    }
    list.appendChild(card);
  });
}

// ── 嚴重度篩選 ──────────────────────────────────────────────────────
function filterFindings(sev) {
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.sev === sev);
  });
  const filtered = sev === 'All' ? _allFindings : _allFindings.filter(f => f.severity === sev);
  renderFindingList(filtered);
}

function resetFilter() {
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.sev === 'All');
  });
}

function buildFindingCard(f, idx) {
  const card = document.createElement('div');
  card.className = 'finding-card';
  card.innerHTML = `
    <div class="finding-hdr" onclick="this.closest('.finding-card').classList.toggle('open')">
      <span class="sev-badge sev-${f.severity}">${esc(f.severity)}</span>
      <span class="finding-type">${esc(f.type)}</span>
      <span class="finding-meta">${esc(f.filename)}<br>${esc(f.line_hint)}</span>
      <span class="chevron">▶</span>
    </div>
    <div class="finding-body">
      <p class="field-lbl">漏洞說明</p>
      <p class="field-val">${esc(f.explanation)}</p>

      <p class="field-lbl">CWE 對應</p>
      <div class="cwe-tags">
        ${f.cwe_references.length
          ? f.cwe_references.map(c => `<span class="cwe-tag">${esc(c)}</span>`).join('')
          : '<span style="color:var(--muted);font-size:0.82rem">無</span>'}
      </div>

      <p class="field-lbl">修復建議</p>
      <pre class="fix-block">${esc(f.fix_suggestion)}</pre>
    </div>`;
  return card;
}

// ── 工具函數 ────────────────────────────────────────────────────────
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function setText(id, val) { document.getElementById(id).textContent = val; }
function showStatus(msg) {
  const bar = document.getElementById('status-bar');
  bar.querySelector('.status-msg').textContent = msg;
  bar.classList.add('visible');
}
function hideStatus() { document.getElementById('status-bar').classList.remove('visible'); }
function showError(msg) {
  const el = document.getElementById('alert-error');
  el.textContent = msg;
  el.classList.add('visible');
}
function hideError() { document.getElementById('alert-error').classList.remove('visible'); }
function setScanning(on) {
  document.getElementById('btn-scan').disabled = on;
}

