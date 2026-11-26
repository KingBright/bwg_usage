use axum::{
    Json,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use tower_http::services::ServeFile;

const DEFAULT_APK_NAME: &str = "zephyr-latest.apk";
const DEFAULT_ICON_NAME: &str = "icon.png";
const DEFAULT_META_NAME: &str = "release.json";
const DEFAULT_VERSION_NAME: &str = "version.json";
const DEFAULT_DESKTOP_VERSION_NAME: &str = "desktop-version.json";
const DEFAULT_MACOS_TAR_NAME: &str = "zephyr-macos-arm64.tar.gz";
const DEFAULT_WINDOWS_EXE_NAME: &str = "zephyr-windows-x64.exe";
const DEFAULT_LINUX_BIN_NAME: &str = "zephyr-linux-x64";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ReleaseMeta {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub size_bytes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VersionInfo {
    pub version: String,
    pub build_number: u32,
    pub size_bytes: u64,
    pub sha256: String,
    pub download_url: String,
    pub release_notes: String,
    pub published_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DesktopPlatformArtifact {
    pub size_bytes: u64,
    pub sha256: String,
    pub download_url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DesktopVersionInfo {
    pub version: String,
    pub build_number: u32,
    pub release_notes: String,
    pub published_at: i64,
    pub platforms: BTreeMap<String, DesktopPlatformArtifact>,
}

pub fn zephyr_dist_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ZEPHYR_DIST_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(static_dir) = std::env::var("STATIC_DIR")
        && let Some(parent) = PathBuf::from(static_dir).parent()
    {
        return parent.join("zephyr_dist");
    }
    PathBuf::from("zephyr_dist")
}

fn nas_base_url() -> String {
    std::env::var("ZEPHYR_NAS_URL")
        .or_else(|_| std::env::var("NAS_SERVER_URL"))
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://your-nas.example.com:8443".to_string())
}

fn short_link_url() -> String {
    format!("{}/z", nas_base_url())
}

pub fn load_version_info(dist_dir: &PathBuf) -> VersionInfo {
    let apk_path = dist_dir.join(DEFAULT_APK_NAME);
    let actual_size = fs::metadata(&apk_path).map(|m| m.len()).unwrap_or(0);
    let default_download_url = format!("{}/zephyr/download/zephyr-latest.apk", nas_base_url());

    let version_path = dist_dir.join(DEFAULT_VERSION_NAME);
    if let Ok(raw) = fs::read_to_string(&version_path)
        && let Ok(mut info) = serde_json::from_str::<VersionInfo>(&raw)
    {
        if actual_size > 0 {
            info.size_bytes = actual_size;
        }
        if info.download_url.trim().is_empty() {
            info.download_url = default_download_url;
        }
        return info;
    }

    let meta = load_release_meta(dist_dir);
    let clean_ver = meta.version.trim().trim_start_matches('v').to_string();
    let version = if clean_ver.is_empty() {
        "1.0.0".to_string()
    } else {
        clean_ver
    };
    let published_at = fs::metadata(&apk_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or_else(|| Local::now().timestamp());

    VersionInfo {
        version,
        build_number: 1,
        size_bytes: if actual_size > 0 {
            actual_size
        } else {
            meta.size_bytes
        },
        sha256: meta.sha256,
        download_url: default_download_url,
        release_notes: "常规优化与稳定性提升".to_string(),
        published_at,
    }
}

/// GET /zephyr/version.json — 公开只读应用更新元数据（免登录，零密钥）
pub async fn zephyr_version_handler() -> impl IntoResponse {
    let dist = zephyr_dist_dir();
    let info = load_version_info(&dist);
    (
        StatusCode::OK,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Json(info),
    )
}

pub fn load_desktop_version_info(dist_dir: &PathBuf) -> DesktopVersionInfo {
    let base = nas_base_url();
    let version_path = dist_dir.join(DEFAULT_DESKTOP_VERSION_NAME);
    let mut info = fs::read_to_string(&version_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<DesktopVersionInfo>(&raw).ok())
        .unwrap_or_else(|| DesktopVersionInfo {
            version: "1.0.4".to_string(),
            build_number: 5,
            release_notes: "桌面端系统接管模式与应用内一键升级".to_string(),
            published_at: Local::now().timestamp(),
            platforms: BTreeMap::new(),
        });

    for (platform_key, filename) in [
        ("macos_arm64", DEFAULT_MACOS_TAR_NAME),
        ("windows_x64", DEFAULT_WINDOWS_EXE_NAME),
        ("linux_x64", DEFAULT_LINUX_BIN_NAME),
    ] {
        let p = dist_dir.join(filename);
        if let Ok(fs_meta) = fs::metadata(&p)
            && fs_meta.is_file()
        {
            let entry = info
                .platforms
                .entry(platform_key.to_string())
                .or_insert_with(|| DesktopPlatformArtifact {
                    size_bytes: fs_meta.len(),
                    sha256: String::new(),
                    download_url: format!("{}/zephyr/download/{}", base, filename),
                });
            entry.size_bytes = fs_meta.len();
            if entry.download_url.trim().is_empty() {
                entry.download_url = format!("{}/zephyr/download/{}", base, filename);
            }
        }
    }

    info
}

/// GET /zephyr/desktop-version.json — 公开只读桌面端多平台更新元数据（免登录，零密钥）
pub async fn zephyr_desktop_version_handler() -> impl IntoResponse {
    let dist = zephyr_dist_dir();
    let info = load_desktop_version_info(&dist);
    (
        StatusCode::OK,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Json(info),
    )
}

fn load_release_meta(dist_dir: &PathBuf) -> ReleaseMeta {
    let meta_path = dist_dir.join(DEFAULT_META_NAME);
    let mut meta = fs::read_to_string(&meta_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<ReleaseMeta>(&raw).ok())
        .unwrap_or_default();

    let apk_path = dist_dir.join(DEFAULT_APK_NAME);
    if let Ok(fs_meta) = fs::metadata(&apk_path) {
        meta.size_bytes = fs_meta.len();
    }
    if meta.version.trim().is_empty() {
        meta.version = "v1.0.0".to_string();
    }
    if meta.updated_at.trim().is_empty() {
        meta.updated_at = "最新构建".to_string();
    }
    meta
}

fn format_size_mb(bytes: u64) -> String {
    if bytes == 0 {
        return "待上传".to_string();
    }
    let mb = (bytes as f64) / (1024.0 * 1024.0);
    format!("{:.1} MB", mb)
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn render_landing_html(meta: &ReleaseMeta, short_url: &str) -> String {
    let version = html_escape(&meta.version);
    let size_text = html_escape(&format_size_mb(meta.size_bytes));
    let updated_at = html_escape(&meta.updated_at);
    let sha_full = html_escape(if meta.sha256.is_empty() {
        "上传后自动生成"
    } else {
        &meta.sha256
    });
    let sha_short = if meta.sha256.len() > 20 {
        html_escape(&format!(
            "{}…{}",
            &meta.sha256[..12],
            &meta.sha256[meta.sha256.len() - 8..]
        ))
    } else {
        sha_full.clone()
    };
    let short_url_esc = html_escape(short_url);

    format!(
        r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <meta name="theme-color" content="#0B192C" />
  <title>Zephyr · 和风 — 极简安装下载</title>
  <link rel="icon" type="image/png" href="/zephyr/icon.png" />
  <style>
    :root {{
      --bg-top: #0B192C;
      --bg-bottom: #0F2537;
      --surface: rgba(255, 255, 255, 0.96);
      --surface-soft: #F0F9FF;
      --border: rgba(14, 165, 233, 0.18);
      --text-main: #0F172A;
      --text-sub: #475569;
      --sky: #0EA5E9;
      --teal: #14B8A6;
      --mint: #2DD4BF;
      --deep: #0B192C;
    }}
    * {{ box-sizing: border-box; -webkit-tap-highlight-color: transparent; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif;
      background: linear-gradient(165deg, var(--bg-top) 0%, #0E2A3F 42%, #F1F8FB 42%, #F8FCFD 100%);
      color: var(--text-main);
      min-height: 100vh;
      line-height: 1.65;
      padding: 20px 16px 40px;
    }}
    .container {{
      max-width: 520px;
      margin: 0 auto;
    }}
    .wx-banner {{
      display: none;
      background: linear-gradient(135deg, #FEF3C7, #FDE68A);
      color: #78350F;
      border: 1px solid #F59E0B;
      border-radius: 16px;
      padding: 14px 16px;
      margin-bottom: 16px;
      font-size: 15px;
      font-weight: 600;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
    }}
    .wx-banner.show {{ display: block; }}
    .hero {{
      text-align: center;
      color: #F8FAFC;
      padding: 14px 8px 24px;
    }}
    .app-icon {{
      width: 92px;
      height: 92px;
      border-radius: 24px;
      box-shadow: 0 14px 32px rgba(14, 165, 233, 0.35), 0 0 0 2px rgba(45, 212, 191, 0.35);
      background: #0B192C;
      object-fit: cover;
    }}
    .title {{
      margin: 14px 0 4px;
      font-size: 28px;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}
    .subtitle {{
      margin: 0;
      font-size: 15px;
      color: #BAE6FD;
    }}
    .card {{
      background: var(--surface);
      border-radius: 22px;
      padding: 22px 20px;
      box-shadow: 0 14px 36px rgba(11, 25, 44, 0.10);
      border: 1px solid var(--border);
      margin-bottom: 16px;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-bottom: 18px;
    }}
    .meta-item {{
      background: var(--surface-soft);
      border-radius: 14px;
      padding: 10px 8px;
      text-align: center;
    }}
    .meta-label {{
      font-size: 12px;
      color: var(--text-sub);
      margin-bottom: 2px;
    }}
    .meta-value {{
      font-size: 15px;
      font-weight: 700;
      color: var(--deep);
    }}
    .download-btn {{
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      width: 100%;
      padding: 16px 20px;
      border-radius: 16px;
      border: none;
      text-decoration: none;
      font-size: 18px;
      font-weight: 700;
      color: #FFFFFF;
      background: linear-gradient(135deg, var(--sky) 0%, var(--teal) 60%, #0D9488 100%);
      box-shadow: 0 10px 24px rgba(14, 165, 233, 0.34);
      transition: transform 0.15s ease, box-shadow 0.15s ease;
    }}
    .download-btn:active {{
      transform: scale(0.985);
      box-shadow: 0 6px 14px rgba(14, 165, 233, 0.28);
    }}
    .sha-box {{
      margin-top: 14px;
      font-size: 12px;
      color: var(--text-sub);
      text-align: center;
      word-break: break-all;
    }}
    .sha-box code {{
      background: #F1F5F9;
      padding: 3px 7px;
      border-radius: 6px;
      color: #334155;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      cursor: pointer;
    }}
    .section-title {{
      margin: 0 0 14px;
      font-size: 18px;
      font-weight: 700;
      color: var(--deep);
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .section-title::before {{
      content: "";
      width: 4px;
      height: 18px;
      border-radius: 4px;
      background: linear-gradient(180deg, var(--sky), var(--mint));
      display: inline-block;
    }}
    .step {{
      display: flex;
      gap: 12px;
      align-items: flex-start;
      margin-bottom: 14px;
    }}
    .step:last-child {{ margin-bottom: 0; }}
    .step-num {{
      flex: 0 0 28px;
      height: 28px;
      border-radius: 50%;
      background: linear-gradient(135deg, var(--sky), var(--teal));
      color: #FFFFFF;
      font-size: 14px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-top: 2px;
    }}
    .step-body {{
      flex: 1;
      font-size: 15px;
      color: #1E293B;
    }}
    .step-body strong {{ color: var(--deep); }}
    .copy-row {{
      margin-top: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
      background: #F0F9FF;
      border: 1px solid rgba(14, 165, 233, 0.25);
      border-radius: 12px;
      padding: 8px 10px;
    }}
    .copy-url {{
      flex: 1;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px;
      color: #0369A1;
      word-break: break-all;
      user-select: all;
    }}
    .copy-btn {{
      flex: 0 0 auto;
      border: none;
      border-radius: 10px;
      padding: 8px 14px;
      font-size: 14px;
      font-weight: 600;
      color: #FFFFFF;
      background: linear-gradient(135deg, var(--sky), var(--teal));
      cursor: pointer;
    }}
    .copy-btn.copied {{
      background: #059669;
    }}
    .tip-list {{
      margin: 0;
      padding-left: 18px;
      font-size: 14px;
      color: #334155;
    }}
    .tip-list li {{
      margin-bottom: 8px;
    }}
    .tip-list li:last-child {{ margin-bottom: 0; }}
    .footer {{
      text-align: center;
      font-size: 12px;
      color: #64748B;
      margin-top: 8px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div id="wxBanner" class="wx-banner">
      检测到正在微信 / QQ 内打开：请点击右上角「⋯」，选择「在浏览器中打开」即可直接下载安装。
    </div>

    <header class="hero">
      <img class="app-icon" src="/zephyr/icon.png" alt="Zephyr 和风" />
      <h1 class="title">Zephyr · 和风</h1>
      <p class="subtitle">轻盈、稳定、开箱即用的私人网络助手</p>
    </header>

    <section class="card">
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">当前版本</div>
          <div class="meta-value">{version}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">安装包体积</div>
          <div class="meta-value">{size_text}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">适用设备</div>
          <div class="meta-value">Android 12+</div>
        </div>
      </div>

      <a class="download-btn" href="/zephyr/download/zephyr-latest.apk" download="Zephyr-android-arm64.apk">
        <span>⬇</span>
        <span>立即下载 Android 安装包</span>
      </a>

      <div class="sha-box">
        更新于 {updated_at} · SHA-256：
        <code id="shaCode" title="点击复制完整校验码" data-full="{sha_full}">{sha_short}</code>
      </div>
    </section>

    <section class="card">
      <h2 class="section-title">桌面版下载（macOS / Windows / Linux）</h2>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;">
        <a href="/zephyr/download/zephyr-macos-arm64.tar.gz" download="zephyr-macos-arm64.tar.gz" style="display:block;text-align:center;padding:12px 10px;border-radius:14px;text-decoration:none;background:#F0F9FF;border:1px solid rgba(14,165,233,0.28);color:#0B192C;font-weight:700;font-size:14px;">
          macOS (Apple Silicon)<br /><span style="font-size:12px;font-weight:500;color:#475569;">.tar.gz 压缩包</span>
        </a>
        <a href="/zephyr/download/zephyr-windows-x64.exe" download="Zephyr-windows-x64.exe" style="display:block;text-align:center;padding:12px 10px;border-radius:14px;text-decoration:none;background:#F0FDFA;border:1px solid rgba(20,184,166,0.28);color:#0B192C;font-weight:700;font-size:14px;">
          Windows (64位)<br /><span style="font-size:12px;font-weight:500;color:#475569;">.exe 免安装直运行</span>
        </a>
        <a href="/zephyr/download/zephyr-linux-x64" download="zephyr-linux-x64" style="display:block;text-align:center;padding:12px 10px;border-radius:14px;text-decoration:none;background:#F5F3FF;border:1px solid rgba(139,92,246,0.28);color:#0B192C;font-weight:700;font-size:14px;">
          Linux (x86_64)<br /><span style="font-size:12px;font-weight:500;color:#475569;">ELF 二进制直运行</span>
        </a>
      </div>
    </section>

    <section class="card">
      <h2 class="section-title">3 步极简上手指南</h2>

      <div class="step">
        <div class="step-num">1</div>
        <div class="step-body">
          <strong>下载并安装 Zephyr</strong><br />
          点击上方绿色按钮下载安装包，完成后点击安装（如系统提示「允许来自此来源的应用」，点击允许即可）。
        </div>
      </div>

      <div class="step">
        <div class="step-num">2</div>
        <div class="step-body">
          <strong>输入短链与密码，一键配置</strong><br />
          打开 Zephyr 进入底部「设置」，粘贴下方配置短链，再填入向管理员获取的密码，点击<strong>「一键配置」</strong>：
          <div class="copy-row">
            <span id="shortLinkText" class="copy-url">{short_url_esc}</span>
            <button id="copyBtn" class="copy-btn" type="button">一键复制</button>
          </div>
        </div>
      </div>

      <div class="step">
        <div class="step-num">3</div>
        <div class="step-body">
          <strong>回到首页，一键开启保护</strong><br />
          切回「首页」点击中间大圆按钮，首次使用会弹出系统网络连接授权提示，点击<strong>「允许 / 确定」</strong>即可畅通使用。
        </div>
      </div>
    </section>

    <section class="card">
      <h2 class="section-title">贴心小贴士</h2>
      <ul class="tip-list">
        <li><strong>微信内打不开下载？</strong>请点击微信右上角「⋯」，选择「在浏览器中打开」后再点下载。</li>
        <li><strong>国产手机长期不断流：</strong>vivo / 华为 / 小米 / OPPO 手机安装后，顺手在「设置」页点一下<strong>「后台保活体检」</strong>放行电池优化，切网和锁屏都能稳稳在线。</li>
        <li><strong>密码请向管理员获取：</strong>本页面不存放任何密码，保障家庭网络安全。</li>
      </ul>
    </section>

    <footer class="footer">Zephyr · 和风 · 家庭直连分发页（国内免翻墙直下）</footer>
  </div>

  <script>
    (function () {{
      var ua = navigator.userAgent || "";
      if (/MicroMessenger|QQ\/|Weibo/i.test(ua)) {{
        document.getElementById("wxBanner").classList.add("show");
      }}

      function copyText(text, onDone) {{
        if (navigator.clipboard && navigator.clipboard.writeText) {{
          navigator.clipboard.writeText(text).then(onDone).catch(function () {{
            fallbackCopy(text, onDone);
          }});
        }} else {{
          fallbackCopy(text, onDone);
        }}
      }}

      function fallbackCopy(text, onDone) {{
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try {{ document.execCommand("copy"); }} catch (e) {{}}
        document.body.removeChild(ta);
        onDone();
      }}

      var copyBtn = document.getElementById("copyBtn");
      var shortLink = document.getElementById("shortLinkText").textContent.trim();
      copyBtn.addEventListener("click", function () {{
        copyText(shortLink, function () {{
          copyBtn.textContent = "已复制 ✓";
          copyBtn.classList.add("copied");
          setTimeout(function () {{
            copyBtn.textContent = "一键复制";
            copyBtn.classList.remove("copied");
          }}, 2000);
        }});
      }});

      var shaEl = document.getElementById("shaCode");
      shaEl.addEventListener("click", function () {{
        var full = shaEl.getAttribute("data-full");
        if (!full) return;
        copyText(full, function () {{
          var orig = shaEl.textContent;
          shaEl.textContent = "已复制完整 SHA-256 ✓";
          setTimeout(function () {{ shaEl.textContent = orig; }}, 1800);
        }});
      }});
    }})();
  </script>
</body>
</html>
"##
    )
}

/// GET /zephyr — 家人友好的公开下载落地页（免登录，零密钥）
pub async fn zephyr_landing_handler() -> impl IntoResponse {
    let dist = zephyr_dist_dir();
    let meta = load_release_meta(&dist);
    let html = render_landing_html(&meta, &short_link_url());
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Html(html),
    )
}

/// GET /zephyr/icon.png — 返回应用图标
pub async fn zephyr_icon_handler(req: Request) -> Response {
    let path = zephyr_dist_dir().join(DEFAULT_ICON_NAME);
    if !path.is_file() {
        return (StatusCode::NOT_FOUND, "icon not found").into_response();
    }
    match ServeFile::new(&path).try_call(req).await {
        Ok(mut resp) => {
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("image/png"),
            );
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            );
            resp.into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "failed to serve icon").into_response(),
    }
}

/// GET / HEAD /zephyr/download/zephyr-latest.apk — 流式下载 APK（支持断点续传）
pub async fn zephyr_apk_download_handler(req: Request) -> Response {
    stream_dist_file(
        req,
        DEFAULT_APK_NAME,
        "application/vnd.android.package-archive",
        "attachment; filename=\"Zephyr-android-arm64.apk\"",
    )
    .await
}

/// GET / HEAD /zephyr/download/zephyr-macos-arm64.tar.gz — 流式下载 macOS 桌面端
pub async fn zephyr_macos_download_handler(req: Request) -> Response {
    stream_dist_file(
        req,
        DEFAULT_MACOS_TAR_NAME,
        "application/gzip",
        "attachment; filename=\"zephyr-macos-arm64.tar.gz\"",
    )
    .await
}

/// GET / HEAD /zephyr/download/zephyr-windows-x64.exe — 流式下载 Windows 桌面端
pub async fn zephyr_windows_download_handler(req: Request) -> Response {
    stream_dist_file(
        req,
        DEFAULT_WINDOWS_EXE_NAME,
        "application/vnd.microsoft.portable-executable",
        "attachment; filename=\"Zephyr-windows-x64.exe\"",
    )
    .await
}

/// GET / HEAD /zephyr/download/zephyr-linux-x64 — 流式下载 Linux x86_64 桌面端
pub async fn zephyr_linux_download_handler(req: Request) -> Response {
    stream_dist_file(
        req,
        DEFAULT_LINUX_BIN_NAME,
        "application/octet-stream",
        "attachment; filename=\"zephyr-linux-x64\"",
    )
    .await
}

async fn stream_dist_file(
    req: Request,
    filename: &str,
    content_type: &'static str,
    content_disposition: &'static str,
) -> Response {
    let path = zephyr_dist_dir().join(filename);
    if !path.is_file() {
        return (StatusCode::NOT_FOUND, "artifact not published yet").into_response();
    }
    match ServeFile::new(&path).try_call(req).await {
        Ok(mut resp) => {
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            resp.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static(content_disposition),
            );
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            resp.into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "failed to stream artifact").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landing_html_contains_required_elements_and_no_secrets() {
        let meta = ReleaseMeta {
            version: "v1.0.0".to_string(),
            sha256: "ee20b3f3f87c590892acbc4c11af7e0e60855ad78253a6f7e2ebe619bd02bdf5".to_string(),
            updated_at: "2026-11-23 13:45".to_string(),
            size_bytes: 34_000_000,
        };
        let html = render_landing_html(&meta, "https://your-nas.example.com:8443/z");
        assert!(html.contains("/zephyr/icon.png"));
        assert!(html.contains("/zephyr/download/zephyr-latest.apk"));
        assert!(html.contains("https://your-nas.example.com:8443/z"));
        assert!(html.contains("3 步极简上手指南"));
        assert!(html.contains("后台保活体检"));
        assert!(html.contains("在浏览器中打开"));
        assert!(html.contains("32.4 MB"));
        assert!(!html.contains("test-secret-pass"));
        assert!(!html.contains("dummy-report-token"));
        assert!(!html.contains("dummy-node-secret"));
    }
}
