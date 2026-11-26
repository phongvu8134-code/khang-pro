(function () {
  const PROFILE_STORAGE_KEY = "kv_profile_v4";
  const LOCAL_AUTH_KEY = "kv_local_auth_v4";
  const LOCAL_SESSION_KEY = "kv_local_session_v4";
  const PBKDF2_ITERATIONS = 100000;

  const PRESET_COLORS = {
    default: ["#f6c945", "#2a9df4", "#ef5350"],
    ocean: ["#67e8f9", "#2563eb", "#818cf8"],
    sunset: ["#fbbf24", "#f97316", "#e11d48"],
    mint: ["#6ee7b7", "#14b8a6", "#60a5fa"]
  };

  const DEFAULT_DATA = {
    name: "Khang Vương",
    subtitle: "Student, C++ CB NC",
    location: "Somewhere in the earth",
    bio: "Who am I?",
    avatarDataUrl: "",
    avatarEffect: "prism",
    bannerMode: "mesh",
    bannerPreset: "default",
    bannerColors: ["#f6c945", "#2a9df4", "#ef5350"],
    bannerImageDataUrl: "",
    bannerPosY: 50,
    bannerDim: 10,
    qrUrl: "",
    buttons: {
      shareLabel: "Share",
      contactLabel: "Contact",
      moneyLabel: "Send money"
    },
    contact: {
      handle: "@KHANG-PRO",
      email: "khangvuong@example.com",
      codeforces: "https://codeforces.com/profile/KHANG-PRO",
      note: "Liên hệ giao lưu C/C++, thuật toán hoặc Minecraft mod."
    },
    money: {
      bank: "Ngân hàng / Ví điện tử",
      accountName: "KHANG VUONG",
      accountNumber: "0000 0000 0000",
      note: "Chỉnh sửa thông tin nhận tiền trong chế độ Admin."
    },
    detailsTitle: "About",
    details: [
      { label: "Focus", value: "C/C++ · Algorithms (Codeforces) · OS Simulation" },
      { label: "Projects", value: "MYOS, VKOS, LiquidGlassOS, VK Ultimate, ChronoEdge Mod" },
      { label: "Goals", value: "B2 First · IELTS 8.0+ · IOI · MIT / Harvard" }
    ]
  };

  let state = structuredClone(DEFAULT_DATA);
  let isAdmin = false;
  let editMode = false;
  let authMode = "local";
  let authInitialized = false;

  const $ = (id) => document.getElementById(id);

  /* ========================================================================
     1. CRYPTO UTILITIES (Salted PBKDF2-SHA256 — Zero Hardcoded Passwords)
     ======================================================================== */
  function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function hexToBytes(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++) {
      arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return arr;
  }

  async function deriveHash(password, saltHex, iterations = PBKDF2_ITERATIONS) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: hexToBytes(saltHex),
        iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );
    return bytesToHex(new Uint8Array(bits));
  }

  async function createLocalPasswordRecord(password) {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const saltHex = bytesToHex(salt);
    const hash = await deriveHash(password, saltHex, PBKDF2_ITERATIONS);
    return { salt: saltHex, hash, iterations: PBKDF2_ITERATIONS };
  }

  async function verifyLocalPassword(password) {
    const raw = localStorage.getItem(LOCAL_AUTH_KEY);
    if (!raw) return false;
    try {
      const rec = JSON.parse(raw);
      const calc = await deriveHash(password, rec.salt, rec.iterations || PBKDF2_ITERATIONS);
      return calc === rec.hash;
    } catch (_) {
      return false;
    }
  }

  /* ========================================================================
     2. CLIENT-SIDE IMAGE RESIZE & COMPRESSION (Avatar & Cover Photo)
     ======================================================================== */
  function compressImage(file, maxW, maxH, squareCrop, quality) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error("Không đọc được file ảnh"));
      reader.onload = () => {
        const img = new Image();
        img.onerror = () => reject(new Error("File không phải ảnh hợp lệ"));
        img.onload = () => {
          const canvas = document.createElement("canvas");
          const ctx = canvas.getContext("2d");

          if (squareCrop) {
            const side = Math.min(img.width, img.height);
            const sx = (img.width - side) / 2;
            const sy = (img.height - side) / 2;
            const outSize = Math.min(side, maxW);
            canvas.width = outSize;
            canvas.height = outSize;
            ctx.drawImage(img, sx, sy, side, side, 0, 0, outSize, outSize);
          } else {
            const ratio = Math.min(maxW / img.width, maxH / img.height, 1);
            canvas.width = Math.round(img.width * ratio);
            canvas.height = Math.round(img.height * ratio);
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          }

          let dataUrl = canvas.toDataURL("image/webp", quality);
          if (!dataUrl.startsWith("data:image/webp")) {
            dataUrl = canvas.toDataURL("image/jpeg", quality);
          }
          resolve(dataUrl);
        };
        img.src = reader.result;
      };
      reader.readAsDataURL(file);
    });
  }

  /* ========================================================================
     3. TOAST & DEEP MERGE
     ======================================================================== */
  let toastTimer = null;
  function showToast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
  }

  function mergeDeep(base, override) {
    const out = structuredClone(base);
    if (!override || typeof override !== "object") return out;
    for (const k of Object.keys(override)) {
      if (
        override[k] &&
        typeof override[k] === "object" &&
        !Array.isArray(override[k]) &&
        out[k] &&
        typeof out[k] === "object"
      ) {
        out[k] = mergeDeep(out[k], override[k]);
      } else if (override[k] !== undefined) {
        out[k] = override[k];
      }
    }
    return out;
  }

  /* ========================================================================
     4. LOAD PROFILE & AUTO-DETECT AUTH STATUS
     ======================================================================== */
  async function initApp() {
    try {
      const res = await fetch("/api/auth/status", { credentials: "same-origin", cache: "no-store" });
      if (res.ok) {
        const info = await res.json();
        authMode = info.kvReady ? "cloud" : "local";
        authInitialized = !!info.initialized;
        if (info.isAdmin) enableAdminUI(false);
      }
    } catch (_) {
      authMode = "local";
    }

    if (authMode === "local") {
      authInitialized = !!localStorage.getItem(LOCAL_AUTH_KEY);
      if (authInitialized && localStorage.getItem(LOCAL_SESSION_KEY) === "active") {
        enableAdminUI(false);
      }
    }

    let loadedCloud = false;
    if (authMode === "cloud") {
      try {
        const res = await fetch("/api/profile", { cache: "no-store" });
        if (res.ok) {
          const json = await res.json();
          if (json && json.name) {
            state = mergeDeep(DEFAULT_DATA, json);
            loadedCloud = true;
          }
        }
      } catch (_) {}
    }

    if (!loadedCloud) {
      try {
        const fileRes = await fetch("profile-data.json", { cache: "no-store" });
        if (fileRes.ok) {
          state = mergeDeep(DEFAULT_DATA, await fileRes.json());
        }
      } catch (_) {}

      try {
        const localSaved = localStorage.getItem(PROFILE_STORAGE_KEY);
        if (localSaved) state = mergeDeep(state, JSON.parse(localSaved));
      } catch (_) {}
    }

    updateSyncStatus();
    render();

    const params = new URLSearchParams(window.location.search);
    if (params.has("admin") && !isAdmin) {
      history.replaceState({}, "", window.location.pathname);
      openAuthModal();
    }
  }

  function updateSyncStatus() {
    const badge = $("syncStatus");
    const info = $("drawerStorageInfo");
    if (authMode === "cloud") {
      badge.textContent = "Cloudflare KV • Cookie bảo mật";
      info.textContent = "Đang đồng bộ Cloudflare KV (lưu vĩnh viễn toàn cầu & bảo mật HttpOnly)";
    } else {
      badge.textContent = "Chế độ Local • PBKDF2";
      info.textContent = "Lưu vĩnh viễn trên thiết bị • Gắn KV trong wrangler.toml để đồng bộ toàn cầu";
    }
  }

  /* ========================================================================
     5. RENDER UI
     ======================================================================== */
  function render() {
    $("fieldName").textContent = state.name;
    $("fieldSubtitle").textContent = state.subtitle;
    $("fieldLocation").textContent = state.location;
    $("fieldBio").textContent = state.bio;
    $("fieldDetailsTitle").textContent = state.detailsTitle || "About";
    document.title = state.name || "Profile";

    $("labelShare").textContent = state.buttons.shareLabel || "Share";
    $("labelContact").textContent = state.buttons.contactLabel || "Contact";
    $("labelMoney").textContent = state.buttons.moneyLabel || "Send money";

    const cols = Array.isArray(state.bannerColors) && state.bannerColors.length === 3
      ? state.bannerColors
      : PRESET_COLORS.default;
    document.documentElement.style.setProperty("--c1", cols[0]);
    document.documentElement.style.setProperty("--c2", cols[1]);
    document.documentElement.style.setProperty("--c3", cols[2]);

    const card = $("profileCard");
    const useImg = state.bannerMode === "image" && !!state.bannerImageDataUrl;
    card.setAttribute("data-banner-mode", useImg ? "image" : "mesh");
    card.setAttribute("data-avatar-effect", state.avatarEffect || "prism");

    const bannerImg = $("customBannerImg");
    if (useImg) {
      bannerImg.src = state.bannerImageDataUrl;
      bannerImg.hidden = false;
      bannerImg.style.setProperty("--banner-pos-y", (state.bannerPosY ?? 50) + "%");
      $("bannerDimLayer").style.setProperty("--banner-dim", ((state.bannerDim ?? 10) / 100).toFixed(2));
    } else {
      bannerImg.hidden = true;
      $("bannerDimLayer").style.setProperty("--banner-dim", "0");
    }

    const customImg = $("customAvatarImg");
    const defaultSvg = $("defaultAvatarSvg");
    if (state.avatarDataUrl) {
      customImg.src = state.avatarDataUrl;
      customImg.hidden = false;
      defaultSvg.style.display = "none";
    } else {
      customImg.hidden = true;
      defaultSvg.style.display = "block";
    }

    const detailList = $("detailList");
    detailList.innerHTML = "";
    (state.details || []).forEach((item) => {
      const row = document.createElement("div");
      row.className = "detail-row";
      row.innerHTML = `<span class="detail-k"></span><span class="detail-v"></span>`;
      row.querySelector(".detail-k").textContent = item.label;
      row.querySelector(".detail-v").textContent = item.value;
      detailList.appendChild(row);
    });
  }

  /* ========================================================================
     6. SAVE PROFILE PERMANENTLY
     ======================================================================== */
  async function saveProfilePermanently() {
    state.name = $("fieldName").textContent.trim() || state.name;
    state.subtitle = $("fieldSubtitle").textContent.trim();
    state.location = $("fieldLocation").textContent.trim();
    state.bio = $("fieldBio").textContent.trim();
    state.detailsTitle = $("fieldDetailsTitle").textContent.trim() || "About";

    if (authMode === "cloud") {
      try {
        const res = await fetch("/api/profile", {
          method: "PUT",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(state)
        });
        if (res.ok) {
          showToast("Đã lưu vĩnh viễn lên Cloudflare KV!");
          return true;
        }
        if (res.status === 401) {
          showToast("Phiên Admin hết hạn, hãy đăng nhập lại.");
          disableAdminUI();
          openAuthModal();
          return false;
        }
      } catch (_) {}
    }

    try {
      localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(state));
      showToast("Đã lưu vĩnh viễn trên thiết bị này!");
      return true;
    } catch (_) {
      showToast("Ảnh quá nặng so với bộ nhớ trình duyệt — hãy thử ảnh nhẹ hơn!");
      return false;
    }
  }

  /* ========================================================================
     7. SECURE ADMIN AUTHENTICATION (First-Time Setup + Login + Password Change)
     ======================================================================== */
  function openAuthModal() {
    const errEl = $("authError");
    errEl.hidden = true;
    $("authPassInput").value = "";
    $("authConfirmInput").value = "";

    if (!authInitialized) {
      $("adminAuthTitle").textContent = "Thiết lập mật khẩu Admin lần đầu";
      $("adminAuthDesc").textContent =
        "Chưa có mật khẩu nào được tạo. Hãy tự đặt mật khẩu riêng (tối thiểu 6 ký tự) — mật khẩu được mã hóa PBKDF2-SHA256 và không bao giờ lưu dạng chữ thường.";
      $("authPassInput").placeholder = "Tạo mật khẩu Admin mới (tối thiểu 6 ký tự)";
      $("authPassInput").setAttribute("autocomplete", "new-password");
      $("authConfirmInput").hidden = false;
      $("authConfirmInput").required = true;
      $("authSubmitBtn").textContent = "Tạo mật khẩu & Đăng nhập";
    } else {
      $("adminAuthTitle").textContent = "Đăng nhập tài khoản Admin";
      $("adminAuthDesc").textContent =
        "Nhập mật khẩu Admin của bạn. Sau khi xác thực, trình duyệt sẽ tự động nhận diện quyền Admin ở các lần truy cập sau.";
      $("authPassInput").placeholder = "Nhập mật khẩu Admin";
      $("authPassInput").setAttribute("autocomplete", "current-password");
      $("authConfirmInput").hidden = true;
      $("authConfirmInput").required = false;
      $("authSubmitBtn").textContent = "Đăng nhập";
    }

    openModal("adminAuthModal");
    setTimeout(() => $("authPassInput").focus(), 70);
  }

  function showAuthError(el, msg) {
    el.textContent = msg;
    el.hidden = false;
  }

  $("adminAuthForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = $("authError");
    errEl.hidden = true;

    const pass = $("authPassInput").value;
    const confirmPass = $("authConfirmInput").value;

    if (pass.length < 6) {
      showAuthError(errEl, "Mật khẩu phải có ít nhất 6 ký tự.");
      return;
    }

    if (!authInitialized) {
      if (pass !== confirmPass) {
        showAuthError(errEl, "Mật khẩu xác nhận không khớp.");
        return;
      }

      if (authMode === "cloud") {
        const res = await fetch("/api/auth/setup", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: pass })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAuthError(errEl, data.error || "Không thể thiết lập mật khẩu.");
          return;
        }
      } else {
        const rec = await createLocalPasswordRecord(pass);
        localStorage.setItem(LOCAL_AUTH_KEY, JSON.stringify(rec));
        localStorage.setItem(LOCAL_SESSION_KEY, "active");
      }

      authInitialized = true;
      closeModal("adminAuthModal");
      enableAdminUI(true);
      showToast("Đã thiết lập mật khẩu Admin thành công!");
      return;
    }

    if (authMode === "cloud") {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pass })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showAuthError(errEl, data.error || "Mật khẩu không chính xác.");
        return;
      }
      closeModal("adminAuthModal");
      enableAdminUI(true);
    } else {
      const ok = await verifyLocalPassword(pass);
      if (!ok) {
        showAuthError(errEl, "Mật khẩu không chính xác.");
        return;
      }
      localStorage.setItem(LOCAL_SESSION_KEY, "active");
      closeModal("adminAuthModal");
      enableAdminUI(true);
    }
  });

  $("changePasswordForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = $("changePassError");
    errEl.hidden = true;

    const currentPassword = $("curPassInput").value;
    const newPassword = $("newPassInput").value;
    const confirmNew = $("confirmNewPassInput").value;

    if (newPassword.length < 6) {
      showAuthError(errEl, "Mật khẩu mới phải có ít nhất 6 ký tự.");
      return;
    }
    if (newPassword !== confirmNew) {
      showAuthError(errEl, "Xác nhận mật khẩu mới không khớp.");
      return;
    }
    if (newPassword === currentPassword) {
      showAuthError(errEl, "Mật khẩu mới phải khác mật khẩu hiện tại.");
      return;
    }

    if (authMode === "cloud") {
      const res = await fetch("/api/auth/change-password", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword, newPassword })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showAuthError(errEl, data.error || "Không thể cập nhật mật khẩu.");
        return;
      }
    } else {
      const ok = await verifyLocalPassword(currentPassword);
      if (!ok) {
        showAuthError(errEl, "Mật khẩu hiện tại không đúng.");
        return;
      }
      const newRec = await createLocalPasswordRecord(newPassword);
      localStorage.setItem(LOCAL_AUTH_KEY, JSON.stringify(newRec));
      localStorage.setItem(LOCAL_SESSION_KEY, "active");
    }

    $("curPassInput").value = "";
    $("newPassInput").value = "";
    $("confirmNewPassInput").value = "";
    showToast("Đã cập nhật mật khẩu Admin vĩnh viễn!");
  });

  function enableAdminUI(announce) {
    isAdmin = true;
    $("adminBar").hidden = false;
    if (announce) showToast("Đã đăng nhập tài khoản Admin");
  }

  function disableAdminUI() {
    isAdmin = false;
    setEditMode(false);
    $("adminBar").hidden = true;
    $("adminDrawer").hidden = true;
  }

  function setEditMode(active) {
    editMode = active;
    document.body.classList.toggle("edit-mode", active);
    $("toggleEditBtn").classList.toggle("active", active);
    $("toggleEditBtn").textContent = active ? "Đang sửa..." : "Sửa nhanh";
    $("saveAllBtn").hidden = !active;

    document.querySelectorAll(".editable-field").forEach((el) => {
      el.setAttribute("contenteditable", active ? "true" : "false");
    });
    if (active) showToast("Chạm vào chữ, ảnh đại diện hoặc nút Đổi ảnh bìa để sửa trực tiếp");
  }

  window.addEventListener("keydown", (e) => {
    if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "a") {
      e.preventDefault();
      if (isAdmin) openDrawer();
      else openAuthModal();
    }
    if (e.key === "Escape") {
      closeAllModals();
      $("adminDrawer").hidden = true;
    }
  });

  let avatarClicks = 0;
  let avatarClickTimer = null;
  $("avatarCircle").addEventListener("click", () => {
    avatarClicks++;
    clearTimeout(avatarClickTimer);
    avatarClickTimer = setTimeout(() => { avatarClicks = 0; }, 1200);
    if (avatarClicks >= 5) {
      avatarClicks = 0;
      if (isAdmin) openDrawer();
      else openAuthModal();
    }
  });

  $("toggleEditBtn").addEventListener("click", () => setEditMode(!editMode));
  $("saveAllBtn").addEventListener("click", async () => {
    const ok = await saveProfilePermanently();
    if (ok) setEditMode(false);
  });

  $("logoutAdminBtn").addEventListener("click", async () => {
    if (authMode === "cloud") {
      try {
        await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
      } catch (_) {}
    } else {
      localStorage.removeItem(LOCAL_SESSION_KEY);
    }
    disableAdminUI();
    showToast("Đã đăng xuất Admin");
  });

  /* ========================================================================
     8. QUICK & DRAWER IMAGE UPLOAD (Avatar + Cover Photo + Banner Colors)
     ======================================================================== */
  async function handleAvatarUpload(file) {
    if (!file) return;
    try {
      state.avatarDataUrl = await compressImage(file, 512, 512, true, 0.86);
      render();
      showToast("Đã tải ảnh đại diện lên! Nhớ bấm Lưu vĩnh viễn.");
    } catch (err) {
      showToast(err.message || "Không thể xử lý ảnh.");
    }
  }

  async function handleBannerUpload(file) {
    if (!file) return;
    try {
      state.bannerImageDataUrl = await compressImage(file, 1400, 600, false, 0.84);
      state.bannerMode = "image";
      syncBannerModeUI();
      render();
      showToast("Đã tải ảnh bìa lên! Nhớ bấm Lưu vĩnh viễn.");
    } catch (err) {
      showToast(err.message || "Không thể xử lý ảnh bìa.");
    }
  }

  $("quickAvatarBtn").addEventListener("click", () => $("quickAvatarInput").click());
  $("quickAvatarInput").addEventListener("change", (e) => handleAvatarUpload(e.target.files[0]));
  $("avatarFileInput").addEventListener("change", (e) => handleAvatarUpload(e.target.files[0]));

  $("quickBannerBtn").addEventListener("click", () => $("quickBannerInput").click());
  $("quickBannerInput").addEventListener("change", (e) => handleBannerUpload(e.target.files[0]));
  $("bannerFileInput").addEventListener("change", (e) => handleBannerUpload(e.target.files[0]));

  $("resetAvatarBtn").addEventListener("click", () => {
    state.avatarDataUrl = "";
    $("avatarFileInput").value = "";
    render();
  });

  $("removeBannerImgBtn").addEventListener("click", () => {
    state.bannerImageDataUrl = "";
    state.bannerMode = "mesh";
    $("bannerFileInput").value = "";
    syncBannerModeUI();
    render();
  });

  function syncBannerModeUI() {
    const mode = state.bannerMode === "image" ? "image" : "mesh";
    document.querySelectorAll("#bannerModeSwitch .mode-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.mode === mode);
    });
    $("bannerMeshControls").hidden = mode !== "mesh";
    $("bannerImageControls").hidden = mode !== "image";
  }

  document.querySelectorAll("#bannerModeSwitch .mode-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.bannerMode = btn.dataset.mode;
      syncBannerModeUI();
      render();
    });
  });

  document.querySelectorAll("#avatarEffectRow .preset-chip").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.avatarEffect = btn.dataset.effect;
      document.querySelectorAll("#avatarEffectRow .preset-chip").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      render();
    });
  });

  document.querySelectorAll("#bannerPresets .preset-chip").forEach((btn) => {
    btn.addEventListener("click", () => {
      const p = btn.dataset.preset;
      state.bannerPreset = p;
      state.bannerMode = "mesh";
      state.bannerColors = [...(PRESET_COLORS[p] || PRESET_COLORS.default)];
      $("colorC1").value = state.bannerColors[0];
      $("colorC2").value = state.bannerColors[1];
      $("colorC3").value = state.bannerColors[2];
      document.querySelectorAll("#bannerPresets .preset-chip").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      syncBannerModeUI();
      render();
    });
  });

  ["colorC1", "colorC2", "colorC3"].forEach((id, idx) => {
    $(id).addEventListener("input", (e) => {
      if (!Array.isArray(state.bannerColors) || state.bannerColors.length !== 3) {
        state.bannerColors = [...PRESET_COLORS.default];
      }
      state.bannerColors[idx] = e.target.value;
      state.bannerPreset = "custom";
      state.bannerMode = "mesh";
      document.querySelectorAll("#bannerPresets .preset-chip").forEach((b) => b.classList.remove("active"));
      render();
    });
  });

  $("bannerPosY").addEventListener("input", (e) => {
    state.bannerPosY = Number(e.target.value);
    $("posYVal").textContent = state.bannerPosY + "%";
    render();
  });

  $("bannerDim").addEventListener("input", (e) => {
    state.bannerDim = Number(e.target.value);
    $("dimVal").textContent = state.bannerDim + "%";
    render();
  });

  function openDrawer() {
    $("inName").value = state.name;
    $("inSubtitle").value = state.subtitle;
    $("inLocation").value = state.location;
    $("inBio").value = state.bio;
    $("inHandle").value = state.contact.handle || "";
    $("inEmail").value = state.contact.email || "";
    $("inCodeforces").value = state.contact.codeforces || "";
    $("inContactNote").value = state.contact.note || "";
    $("inBank").value = state.money.bank || "";
    $("inAccName").value = state.money.accountName || "";
    $("inAccNum").value = state.money.accountNumber || "";
    $("inDetails").value = (state.details || []).map((d) => `${d.label} | ${d.value}`).join("\n");

    const cols = state.bannerColors || PRESET_COLORS.default;
    $("colorC1").value = cols[0];
    $("colorC2").value = cols[1];
    $("colorC3").value = cols[2];

    $("bannerPosY").value = state.bannerPosY ?? 50;
    $("posYVal").textContent = (state.bannerPosY ?? 50) + "%";
    $("bannerDim").value = state.bannerDim ?? 10;
    $("dimVal").textContent = (state.bannerDim ?? 10) + "%";

    document.querySelectorAll("#avatarEffectRow .preset-chip").forEach((b) => {
      b.classList.toggle("active", b.dataset.effect === (state.avatarEffect || "prism"));
    });
    document.querySelectorAll("#bannerPresets .preset-chip").forEach((b) => {
      b.classList.toggle("active", b.dataset.preset === state.bannerPreset);
    });
    syncBannerModeUI();
    $("changePassError").hidden = true;
    $("adminDrawer").hidden = false;
  }

  $("openDrawerBtn").addEventListener("click", openDrawer);
  $("closeDrawerBtn").addEventListener("click", () => { $("adminDrawer").hidden = true; });

  $("drawerSaveBtn").addEventListener("click", async () => {
    state.name = $("inName").value.trim() || "Khang Vương";
    state.subtitle = $("inSubtitle").value.trim();
    state.location = $("inLocation").value.trim();
    state.bio = $("inBio").value.trim();
    state.contact.handle = $("inHandle").value.trim();
    state.contact.email = $("inEmail").value.trim();
    state.contact.codeforces = $("inCodeforces").value.trim();
    state.contact.note = $("inContactNote").value.trim();
    state.money.bank = $("inBank").value.trim();
    state.money.accountName = $("inAccName").value.trim();
    state.money.accountNumber = $("inAccNum").value.trim();

    state.details = $("inDetails")
      .value.split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const parts = line.split("|");
        return {
          label: (parts[0] || "Info").trim(),
          value: (parts.slice(1).join("|") || "").trim()
        };
      });

    render();
    const ok = await saveProfilePermanently();
    if (ok) $("adminDrawer").hidden = true;
  });

  $("exportJsonBtn").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "profile-data.json";
    a.click();
    URL.revokeObjectURL(url);
    showToast("Đã tải profile-data.json!");
  });

  $("resetDefaultBtn").addEventListener("click", () => {
    state = structuredClone(DEFAULT_DATA);
    render();
    openDrawer();
    showToast("Đã khôi phục nội dung gốc (bấm Lưu để xác nhận)");
  });

  /* ========================================================================
     9. PUBLIC MODALS: SHARE / QR, CONTACT, SEND MONEY
     ======================================================================== */
  function openModal(id) { $(id).hidden = false; }
  function closeModal(id) { $(id).hidden = true; }
  function closeAllModals() {
    document.querySelectorAll(".modal-backdrop").forEach((m) => { m.hidden = true; });
  }

  document.querySelectorAll("[data-close]").forEach((btn) => {
    btn.addEventListener("click", () => closeModal(btn.dataset.close));
  });
  document.querySelectorAll(".modal-backdrop").forEach((bg) => {
    bg.addEventListener("click", (e) => { if (e.target === bg) bg.hidden = true; });
  });

  function openShareModal() {
    const url = state.qrUrl || window.location.href;
    $("shareUrlText").textContent = url;
    drawStylishQr($("qrCanvas"), url);
    openModal("qrModal");
  }

  $("qrBtn").addEventListener("click", openShareModal);
  $("shareBtn").addEventListener("click", openShareModal);

  $("copyLinkBtn").addEventListener("click", async () => {
    const url = state.qrUrl || window.location.href;
    try {
      await navigator.clipboard.writeText(url);
      showToast("Đã sao chép liên kết!");
    } catch (_) {
      showToast(url);
    }
  });

  $("nativeShareBtn").addEventListener("click", async () => {
    const url = state.qrUrl || window.location.href;
    if (navigator.share) {
      try { await navigator.share({ title: state.name, text: state.subtitle, url }); } catch (_) {}
    } else {
      try {
        await navigator.clipboard.writeText(url);
        showToast("Đã sao chép liên kết!");
      } catch (_) {}
    }
  });

  function buildInfoRow(label, value, isLink) {
    const row = document.createElement("div");
    row.className = "info-item";
    const left = document.createElement("div");
    const sm = document.createElement("small");
    sm.textContent = label;
    left.appendChild(sm);

    if (isLink && value.startsWith("http")) {
      const a = document.createElement("a");
      a.href = value;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = value;
      left.appendChild(a);
    } else {
      const st = document.createElement("strong");
      st.textContent = value || "—";
      left.appendChild(st);
    }

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-mini";
    btn.textContent = "Copy";
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(value);
        showToast(`Đã sao chép ${label}`);
      } catch (_) {}
    });

    row.appendChild(left);
    row.appendChild(btn);
    return row;
  }

  $("contactBtn").addEventListener("click", () => {
    $("contactNote").textContent = state.contact.note || "";
    const box = $("contactRows");
    box.innerHTML = "";
    if (state.contact.handle) box.appendChild(buildInfoRow("Handle", state.contact.handle, false));
    if (state.contact.email) box.appendChild(buildInfoRow("Email", state.contact.email, false));
    if (state.contact.codeforces) box.appendChild(buildInfoRow("Codeforces", state.contact.codeforces, true));
    openModal("contactModal");
  });

  $("moneyBtn").addEventListener("click", () => {
    $("moneyNote").textContent = state.money.note || "";
    const box = $("moneyRows");
    box.innerHTML = "";
    box.appendChild(buildInfoRow("Ngân hàng / Ví", state.money.bank, false));
    box.appendChild(buildInfoRow("Chủ tài khoản", state.money.accountName, false));
    box.appendChild(buildInfoRow("Số tài khoản", state.money.accountNumber, false));
    openModal("moneyModal");
  });

  /* ========================================================================
     10. REAL ISO/IEC 18004 SCANNABLE QR CODE (Byte Mode, ECC-M)
     ======================================================================== */
  function drawStylishQr(canvas, text) {
    const bytes = Array.from(new TextEncoder().encode(text));
    const SPECS = [
      null,
      { size: 21, total: 26, data: 16, ecc: 10, align: [] },
      { size: 25, total: 44, data: 28, ecc: 16, align: [6, 18] },
      { size: 29, total: 70, data: 44, ecc: 26, align: [6, 22] },
      { size: 33, total: 100, data: 64, ecc: 36, align: [6, 26] },
      { size: 37, total: 134, data: 86, ecc: 48, align: [6, 30] },
      { size: 41, total: 172, data: 108, ecc: 64, align: [6, 34] }
    ];

    let ver = 1;
    while (ver < SPECS.length && bytes.length + 2 > SPECS[ver].data) ver++;
    if (ver >= SPECS.length) ver = SPECS.length - 1;
    const spec = SPECS[ver];
    const n = spec.size;

    const bits = [];
    const pushBits = (val, len) => {
      for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
    };
    pushBits(0b0100, 4);
    const payload = bytes.slice(0, spec.data - 2);
    pushBits(payload.length, 8);
    payload.forEach((b) => pushBits(b, 8));
    pushBits(0, Math.min(4, spec.data * 8 - bits.length));
    while (bits.length % 8 !== 0) bits.push(0);

    const dataCodewords = [];
    for (let i = 0; i < bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
      dataCodewords.push(byte);
    }
    const pads = [0xec, 0x11];
    while (dataCodewords.length < spec.data) {
      dataCodewords.push(pads[dataCodewords.length % 2]);
    }

    const gfMul = (x, y) => {
      let r = 0;
      for (let i = 0; i < 8; i++) if (y & (1 << i)) r ^= x << i;
      for (let i = 14; i >= 8; i--) if (r & (1 << i)) r ^= 0x11d << (i - 8);
      return r;
    };
    let gen = [1];
    for (let i = 0; i < spec.ecc; i++) {
      let a = 1;
      for (let k = 0; k < i; k++) a = gfMul(a, 2);
      const nxt = new Array(gen.length + 1).fill(0);
      for (let j = 0; j < gen.length; j++) {
        nxt[j] ^= gen[j];
        nxt[j + 1] ^= gfMul(gen[j], a);
      }
      gen = nxt;
    }
    const rem = new Array(spec.ecc).fill(0);
    for (const b of dataCodewords) {
      const f = b ^ rem.shift();
      rem.push(0);
      for (let j = 0; j < spec.ecc; j++) rem[j] ^= gfMul(gen[j + 1], f);
    }
    const allCodewords = dataCodewords.concat(rem);

    const mod = Array.from({ length: n }, () => new Array(n).fill(null));
    const isFunc = Array.from({ length: n }, () => new Array(n).fill(false));
    const setFunc = (r, c, v) => {
      if (r >= 0 && r < n && c >= 0 && c < n) {
        mod[r][c] = v ? 1 : 0;
        isFunc[r][c] = true;
      }
    };

    const placeFinder = (sr, sc) => {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const inBox = r >= 0 && r <= 6 && c >= 0 && c <= 6;
          const dark =
            inBox &&
            (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
          setFunc(sr + r, sc + c, dark);
        }
      }
    };
    placeFinder(0, 0);
    placeFinder(0, n - 7);
    placeFinder(n - 7, 0);

    if (spec.align.length === 2) {
      const ac = spec.align[1];
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const dark = Math.max(Math.abs(r), Math.abs(c)) !== 1;
          setFunc(ac + r, ac + c, dark);
        }
      }
    }

    for (let i = 8; i < n - 8; i++) {
      setFunc(6, i, i % 2 === 0);
      setFunc(i, 6, i % 2 === 0);
    }
    setFunc(n - 8, 8, 1);

    for (let i = 0; i < 9; i++) {
      if (!isFunc[8][i]) isFunc[8][i] = true;
      if (!isFunc[i][8]) isFunc[i][8] = true;
    }
    for (let i = 0; i < 8; i++) {
      isFunc[8][n - 1 - i] = true;
      isFunc[n - 1 - i][8] = true;
    }

    const bitStream = [];
    allCodewords.forEach((cw) => {
      for (let b = 7; b >= 0; b--) bitStream.push((cw >>> b) & 1);
    });
    let idx = 0;
    let upward = true;
    for (let right = n - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let step = 0; step < n; step++) {
        const r = upward ? n - 1 - step : step;
        for (let dx = 0; dx < 2; dx++) {
          const c = right - dx;
          if (!isFunc[r][c]) {
            const bit = idx < bitStream.length ? bitStream[idx++] : 0;
            mod[r][c] = bit ^ ((r + c) % 2 === 0 ? 1 : 0);
          }
        }
      }
      upward = !upward;
    }

    const FMT = 0b101010000010010;
    const fmtBit = (i) => (FMT >>> i) & 1;
    const fCoords1 = [
      [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
      [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]
    ];
    fCoords1.forEach(([r, c], i) => { mod[r][c] = fmtBit(14 - i); });
    for (let i = 0; i < 8; i++) mod[8][n - 1 - i] = fmtBit(i);
    for (let i = 0; i < 7; i++) mod[n - 7 + i][8] = fmtBit(14 - i);

    const ctx = canvas.getContext("2d");
    const size = canvas.width;
    const pad = 16;
    const cell = (size - pad * 2) / n;

    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, size, size);

    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (mod[r][c]) {
          ctx.fillStyle = "#0f172a";
          ctx.fillRect(
            Math.floor(pad + c * cell),
            Math.floor(pad + r * cell),
            Math.ceil(cell),
            Math.ceil(cell)
          );
        }
      }
    }

    const badge = Math.round(size * 0.14);
    ctx.fillStyle = "#ffffff";
    ctx.beginPath();
    ctx.roundRect(size / 2 - badge / 2 - 2, size / 2 - badge / 2 - 2, badge + 4, badge + 4, 7);
    ctx.fill();

    ctx.fillStyle = "#1d4ed8";
    ctx.beginPath();
    ctx.roundRect(size / 2 - badge / 2, size / 2 - badge / 2, badge, badge, 6);
    ctx.fill();

    ctx.fillStyle = "#ffffff";
    ctx.font = "700 11px 'Be Vietnam Pro', sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("KV", size / 2, size / 2 + 0.5);
  }

  /* ========================================================================
     11. TACTILE MICRO-INTERACTIONS (Card Glow + Avatar 3D Specular + Ripple)
     ======================================================================== */
  document.querySelectorAll(".profile-card, .secondary-card").forEach((card) => {
    card.addEventListener("pointermove", (e) => {
      const r = card.getBoundingClientRect();
      const x = e.clientX - r.left;
      const y = e.clientY - r.top;
      card.style.setProperty("--mx", x.toFixed(1) + "px");
      card.style.setProperty("--my", y.toFixed(1) + "px");
      card.style.setProperty("--hover", "1");

      const rx = ((y / r.height) - 0.5) * -2.0;
      const ry = ((x / r.width) - 0.5) * 2.0;
      card.style.transform = `perspective(1200px) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) translateY(-2px)`;
    });

    card.addEventListener("pointerleave", () => {
      card.style.setProperty("--hover", "0");
      card.style.transform = "";
    });
  });

  const avatarWrap = $("avatarWrap");
  avatarWrap.addEventListener("pointermove", (e) => {
    const r = avatarWrap.getBoundingClientRect();
    const x = e.clientX - r.left;
    const y = e.clientY - r.top;
    const rx = ((y / r.height) - 0.5) * -14;
    const ry = ((x / r.width) - 0.5) * 14;
    avatarWrap.style.setProperty("--ax", x.toFixed(1) + "px");
    avatarWrap.style.setProperty("--ay", y.toFixed(1) + "px");
    avatarWrap.style.transform = `translateY(-5px) perspective(600px) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) scale(1.04)`;
  });
  avatarWrap.addEventListener("pointerleave", () => {
    avatarWrap.style.transform = "";
  });

  document.querySelectorAll(".action-btn").forEach((btn) => {
    btn.addEventListener("pointerdown", (e) => {
      const r = btn.getBoundingClientRect();
      const span = document.createElement("span");
      span.className = "ripple";
      const size = Math.max(r.width, r.height);
      span.style.width = span.style.height = size + "px";
      span.style.left = e.clientX - r.left - size / 2 + "px";
      span.style.top = e.clientY - r.top - size / 2 + "px";
      btn.appendChild(span);
      setTimeout(() => span.remove(), 650);
    });
  });

  initApp();
})();
