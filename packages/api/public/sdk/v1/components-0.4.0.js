/* @qrauth/web-components v0.4.0 — https://qrauth.io */
"use strict";var QRAuthComponents=(()=>{var v=Object.defineProperty;var k=Object.getOwnPropertyDescriptor;var E=Object.getOwnPropertyNames;var I=Object.prototype.hasOwnProperty;var S=(o,a,t)=>a in o?v(o,a,{enumerable:!0,configurable:!0,writable:!0,value:t}):o[a]=t;var A=(o,a)=>{for(var t in a)v(o,t,{get:a[t],enumerable:!0})},T=(o,a,t,e)=>{if(a&&typeof a=="object"||typeof a=="function")for(let i of E(a))!I.call(o,i)&&i!==t&&v(o,i,{get:()=>a[i],enumerable:!(e=k(a,i))||e.enumerable});return o};var C=o=>T(v({},"__esModule",{value:!0}),o);var n=(o,a,t)=>S(o,typeof a!="symbol"?a+"":a,t);var $={};A($,{QRAuthElement:()=>p,QRAuthEphemeral:()=>b,QRAuthLogin:()=>g,QRAuthTwoFA:()=>m});var p=class extends HTMLElement{constructor(){super();n(this,"shadow");n(this,"_sseConnection",null);n(this,"_pollInterval",null);this.shadow=this.attachShadow({mode:"open"})}static get observedAttributes(){return["tenant","theme","base-url","force-mode","mobile-fallback-only"]}get tenant(){return this.getAttribute("tenant")||""}get theme(){return this.getAttribute("theme")||"light"}get baseUrl(){let t=this.getAttribute("base-url");return t!==null?t:"https://qrauth.io"}connectedCallback(){this.render()}disconnectedCallback(){this.cleanup()}attributeChangedCallback(t,e,i){e!==i&&this.render()}isMobileLike(){if(typeof window>"u")return!1;let t=this.getAttribute("force-mode");if(t==="mobile")return!0;if(t==="desktop"||this.hasAttribute("mobile-fallback-only"))return!1;if(typeof window.matchMedia=="function"){let e=window.matchMedia("(pointer: coarse)").matches,i=window.matchMedia("(hover: none)").matches;if(e&&i)return!0}return/Android|iPhone|iPad|iPod|Mobile|Tablet|BlackBerry|Opera Mini/i.test(navigator.userAgent)}connectSSE(t){this.disconnectSSE(),this._sseConnection=new EventSource(t),this._sseConnection.onerror=()=>{this.disconnectSSE()}}onSSEEvent(t,e){this._sseConnection&&this._sseConnection.addEventListener(t,i=>{let r=i;try{e(JSON.parse(r.data))}catch{}})}disconnectSSE(){this._sseConnection&&(this._sseConnection.close(),this._sseConnection=null)}startPolling(t,e,i,r){this.stopPolling();let s=async()=>{try{let d=await fetch(t,{headers:r});d.ok&&i(await d.json())}catch{}};s(),this._pollInterval=setInterval(s,e)}stopPolling(){this._pollInterval&&(clearInterval(this._pollInterval),this._pollInterval=null)}cleanup(){this.disconnectSSE(),this.stopPolling()}emit(t,e){this.dispatchEvent(new CustomEvent(t,{bubbles:!0,composed:!0,detail:e}))}async generateCodeVerifier(){let t=new Uint8Array(32);return crypto.getRandomValues(t),this._base64url(t)}async computeCodeChallenge(t){let i=new TextEncoder().encode(t),r=await crypto.subtle.digest("SHA-256",i);return this._base64url(new Uint8Array(r))}_base64url(t){let e=Array.from(t,i=>String.fromCodePoint(i)).join("");return btoa(e).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}getBaseStyles(){return`
      :host {
        display: inline-block;
        font-family: var(--qrauth-font, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif);
        --_primary:       var(--qrauth-primary, #00a76f);
        --_primary-dark:  var(--qrauth-primary-dark, #007a52);
        --_text:          var(--qrauth-text, #1a1a2e);
        --_text-muted:    var(--qrauth-text-muted, #637381);
        --_bg:            var(--qrauth-bg, #ffffff);
        --_surface:       var(--qrauth-surface, #f9fafb);
        --_border:        var(--qrauth-border, #e0e0e0);
        --_radius:        var(--qrauth-radius, 12px);
        --_shadow:        var(--qrauth-shadow, 0 24px 48px rgba(0,0,0,0.15));
        --_btn-bg:        var(--qrauth-btn-bg, #1b2a4a);
        --_btn-hover:     var(--qrauth-btn-hover, #263b66);
        --_success:       #00a76f;
        --_error:         #ff5630;
        --_warning:       #ffab00;
        --_disabled:      #919eab;
      }
      :host([theme="dark"]) {
        --_text:       var(--qrauth-text, #f0f0f0);
        --_text-muted: var(--qrauth-text-muted, #919eab);
        --_bg:         var(--qrauth-bg, #1a1a2e);
        --_surface:    var(--qrauth-surface, #242436);
        --_border:     var(--qrauth-border, rgba(255,255,255,0.12));
        --_shadow:     var(--qrauth-shadow, 0 24px 48px rgba(0,0,0,0.5));
        --_btn-bg:     var(--qrauth-btn-bg, #263b66);
        --_btn-hover:  var(--qrauth-btn-hover, #2e4578);
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
    `}};var u=`<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z"
        fill="none" stroke="#fff" stroke-width="5"/>
  <g fill="#fff" opacity="0.2">
    <rect x="52" y="40" width="18" height="18" rx="3"/>
    <rect x="78" y="40" width="18" height="18" rx="3"/>
    <rect x="130" y="40" width="18" height="18" rx="3"/>
    <rect x="52" y="66" width="18" height="18" rx="3"/>
    <rect x="104" y="66" width="18" height="18" rx="3"/>
    <rect x="78" y="92" width="18" height="18" rx="3"/>
    <rect x="130" y="92" width="18" height="18" rx="3"/>
    <rect x="52" y="118" width="18" height="18" rx="3"/>
    <rect x="104" y="118" width="18" height="18" rx="3"/>
  </g>
  <path d="M62 104 L88 134 L144 64"
        fill="none" stroke="#fff" stroke-width="15"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`,_=`<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" fill="currentColor"/>
</svg>`,B=`<svg class="spinner" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2.5"
          stroke-dasharray="31.416" stroke-dashoffset="10" stroke-linecap="round"/>
</svg>`,g=class extends p{constructor(){super(...arguments);n(this,"_sessionId",null);n(this,"_sessionToken",null);n(this,"_codeVerifier",null);n(this,"_status","idle");n(this,"_expiresAt",null);n(this,"_timerInterval",null);n(this,"_pollTimeout",null)}static get observedAttributes(){return[...super.observedAttributes,"scopes","redirect-url","on-auth","display","animated","redirect-uri"]}get scopes(){return this.getAttribute("scopes")||"identity"}get redirectUrl(){return this.getAttribute("redirect-url")}get onAuth(){return this.getAttribute("on-auth")}get display(){return this.getAttribute("display")||"button"}get animated(){return this.hasAttribute("animated")}get redirectUri(){return this.getAttribute("redirect-uri")}get forceMode(){let t=this.getAttribute("force-mode");return t==="mobile"||t==="desktop"?t:"auto"}get mobileFallbackOnly(){return this.hasAttribute("mobile-fallback-only")}disconnectedCallback(){super.disconnectedCallback(),this._clearTimers()}render(){this.display==="inline"?this._renderInline():this._renderButton()}_renderButton(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: inline-block; }

        .btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          user-select: none;
          line-height: 1.4;
          font-family: inherit;
        }
        .btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(27,42,74,0.3);
        }
        .btn:active:not(:disabled) { transform: translateY(0); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        /* Modal overlay */
        .overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.55);
          z-index: 99999;
          display: flex;
          align-items: center;
          justify-content: center;
          animation: fade-in 0.2s ease;
        }
        .overlay.hidden { display: none; }

        @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slide-up {
          from { transform: translateY(24px); opacity: 0; }
          to   { transform: translateY(0); opacity: 1; }
        }

        .modal {
          background: var(--_bg);
          border-radius: 16px;
          padding: 32px 28px 24px;
          max-width: 380px;
          width: 90vw;
          box-shadow: var(--_shadow);
          text-align: center;
          animation: slide-up 0.3s ease;
          position: relative;
        }

        ${this._sharedModalStyles()}
      </style>

      <button class="btn" id="open-btn" aria-label="Sign in with QRAuth">
        <span class="btn-icon">${u}</span>
        Sign in with QRAuth
      </button>

      <div class="overlay hidden" id="overlay" role="dialog" aria-modal="true" aria-label="QRAuth sign-in">
        <div class="modal">
          ${this._modalContent()}
        </div>
      </div>
    `,this._bindButtonEvents()}_renderInline(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: block; }

        .inline-container {
          background: var(--_bg);
          border: 1px solid var(--_border);
          border-radius: 16px;
          padding: 28px 24px 20px;
          text-align: center;
          max-width: 360px;
          margin: 0 auto;
        }

        /* Idle state: show start button */
        .start-btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: inherit;
          width: 100%;
          justify-content: center;
        }
        .start-btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
        }
        .start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        ${this._sharedModalStyles()}
      </style>

      <div class="inline-container">
        <div id="inline-body">
          ${this._inlineIdleContent()}
        </div>
      </div>
    `,this._bindInlineEvents()}_inlineIdleContent(){return`
      <button class="start-btn" id="start-btn" aria-label="Sign in with QRAuth">
        <span class="btn-icon">${u}</span>
        Sign in with QRAuth
      </button>
    `}_modalContent(){return`
      <button class="close-btn" id="close-btn" aria-label="Close">&times;</button>
      <div id="modal-body">
        ${this._bodyForStatus("idle")}
      </div>
    `}_bodyForStatus(t,e){switch(t){case"idle":return`
          <div class="state-header">
            <div class="brand-icon">${u}</div>
            <h3>Sign in with QRAuth</h3>
            <p>Secure, passwordless authentication</p>
          </div>
        `;case"loading":return`
          <div class="state-loading">
            <div class="spinner-wrap">${B}</div>
            <p class="status-text">Generating QR code...</p>
          </div>
        `;case"pending":case"SCANNED":{if(this.isMobileLike())return this._mobilePendingBody(t,e);let i=t==="SCANNED";return`
          <h3>Sign in with QRAuth</h3>
          <p class="subtitle">Scan this QR code with your phone camera</p>
          ${this._qrFrameHtml(e?.qrUrl??"",i)}
          <div class="status-text ${i?"status-scanned":""}">
            ${i?"&#10003; QR code scanned &mdash; waiting for approval...":"Waiting for scan..."}
          </div>
          <div class="timer" id="timer">${e?.timerHtml??""}</div>
          <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
        `}case"APPROVED":return`
          <div class="state-approved">
            <div class="success-icon">${_}</div>
            <h3>Identity verified!</h3>
            <p class="subtitle">You are now signed in</p>
          </div>
        `;case"DENIED":return`
          <div class="state-denied">
            <div class="error-icon">&#10007;</div>
            <h3>Authentication denied</h3>
            <p class="subtitle">The request was declined on your device.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;case"EXPIRED":return`
          <div class="state-expired">
            <div class="expired-icon">&#8987;</div>
            <h3>Session expired</h3>
            <p class="subtitle">The QR code has timed out.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;case"error":return`
          <div class="state-error">
            <div class="error-icon">&#9888;</div>
            <h3>Something went wrong</h3>
            <p class="subtitle">${e?.errorMessage??"Failed to start authentication."}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;default:return""}}_qrFrameHtml(t,e){let i=t?`https://api.qrserver.com/v1/create-qr-code/?size=440x440&data=${encodeURIComponent(t)}`:"";return`
      <div class="qr-frame ${e?"scanned":""}${this.animated?" animated":""}">
        <img src="${i}" alt="QR Code for authentication" width="220" height="220" loading="lazy"/>
        <div class="qr-badge">${u}</div>
        ${e?'<div class="scanned-overlay"><span class="scanned-check">'+_+"</span></div>":""}
      </div>
    `}_mobilePendingBody(t,e){let i=t==="SCANNED";return`
      <h3>Sign in with QRAuth</h3>
      <p class="subtitle">Tap continue to verify on this device.</p>
      <button class="mobile-cta" id="mobile-cta" type="button">
        <span class="btn-icon">${u}</span>
        Continue with QRAuth
      </button>
      <div class="status-text ${i?"status-scanned":""}">
        ${i?"&#10003; Scanned &mdash; waiting for approval...":"Waiting for approval..."}
      </div>
      <div class="timer" id="timer">${e?.timerHtml??""}</div>
      <details class="alt-device">
        <summary>Use another device</summary>
        ${this._qrFrameHtml(e?.qrUrl??"",i)}
      </details>
      <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
    `}_sharedModalStyles(){return`
      /* Typography */
      h3 {
        font-size: 18px;
        font-weight: 700;
        color: var(--_text);
        margin: 0 0 6px;
      }
      .subtitle {
        font-size: 13px;
        color: var(--_text-muted);
        margin: 0 0 20px;
        line-height: 1.5;
      }

      /* Close button */
      .close-btn {
        position: absolute;
        top: 12px;
        right: 14px;
        background: none;
        border: none;
        cursor: pointer;
        color: var(--_text-muted);
        font-size: 22px;
        line-height: 1;
        padding: 4px 6px;
        border-radius: 6px;
        transition: color 0.15s, background 0.15s;
        font-family: inherit;
      }
      .close-btn:hover { color: var(--_text); background: var(--_surface); }

      /* Brand icon in idle state */
      .state-header { padding: 8px 0 4px; }
      .brand-icon {
        width: 56px;
        height: 56px;
        background: var(--_btn-bg);
        border-radius: 14px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 14px;
        padding: 10px;
      }
      .brand-icon svg { width: 36px; height: 36px; }

      /* Loading state */
      .state-loading {
        padding: 32px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
      }
      .spinner-wrap { color: var(--_primary); }
      .spinner {
        width: 40px;
        height: 40px;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      /* QR frame */
      .qr-frame {
        display: inline-block;
        padding: 14px;
        background: #fff;
        border: 2px solid var(--_border);
        border-radius: var(--_radius);
        margin-bottom: 14px;
        position: relative;
        transition: border-color 0.3s;
      }
      .qr-frame.scanned { border-color: var(--_success); }
      .qr-frame.animated { animation: qr-pulse 2s ease-in-out infinite; }
      @keyframes qr-pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(0,167,111,0); }
        50% { box-shadow: 0 0 0 8px rgba(0,167,111,0.15); }
      }
      .qr-frame img { display: block; width: 220px; height: 220px; border-radius: 4px; }
      .qr-badge {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 52px;
        height: 52px;
        background: #1b2a4a;
        border-radius: 10px;
        padding: 6px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .qr-badge svg { width: 100%; height: 100%; }

      /* Scanned overlay on QR */
      .scanned-overlay {
        position: absolute;
        inset: 0;
        background: rgba(0,167,111,0.08);
        border-radius: calc(var(--_radius) - 2px);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .scanned-check {
        width: 48px;
        height: 48px;
        background: var(--_success);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        opacity: 0;
        animation: pop-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.1s forwards;
      }
      .scanned-check svg { width: 28px; height: 28px; }
      @keyframes pop-in {
        from { transform: scale(0.5); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }

      /* Status text */
      .status-text {
        font-size: 13px;
        color: var(--_text-muted);
        min-height: 20px;
      }
      .status-scanned {
        color: var(--_success);
        font-weight: 600;
      }

      /* Timer */
      .timer {
        font-size: 12px;
        color: var(--_disabled);
        margin-top: 8px;
        font-variant-numeric: tabular-nums;
        min-height: 18px;
      }

      /* Success state */
      .state-approved {
        padding: 24px 0 12px;
        animation: fade-scale-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      }
      @keyframes fade-scale-in {
        from { transform: scale(0.85); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }
      .success-icon {
        width: 64px;
        height: 64px;
        background: var(--_success);
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        margin-bottom: 16px;
      }
      .success-icon svg { width: 36px; height: 36px; }

      /* Denied / expired / error states */
      .state-denied, .state-expired, .state-error {
        padding: 20px 0 8px;
      }
      .error-icon, .expired-icon {
        font-size: 48px;
        margin-bottom: 12px;
        line-height: 1;
        display: block;
      }
      .state-denied .error-icon   { color: var(--_error); }
      .state-expired .expired-icon { color: var(--_disabled); }
      .state-error .error-icon    { color: var(--_warning); }

      /* Retry button */
      .retry-btn {
        margin-top: 14px;
        padding: 9px 22px;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        color: var(--_text-muted);
        font-family: inherit;
        transition: background 0.15s, border-color 0.15s;
      }
      .retry-btn:hover { background: var(--_border); color: var(--_text); }

      /* Mobile-aware pending state: primary CTA + QR expander */
      .mobile-cta {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        width: 100%;
        padding: 14px 20px;
        background: var(--_btn-bg);
        color: #fff;
        border: none;
        border-radius: var(--_radius);
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        font-family: inherit;
        margin-bottom: 16px;
      }
      .mobile-cta:hover { background: var(--_btn-hover); }
      .mobile-cta .btn-icon { width: 20px; height: 20px; }

      details.alt-device {
        margin-top: 14px;
        text-align: left;
        border-top: 1px solid var(--_border);
        padding-top: 12px;
      }
      details.alt-device summary {
        cursor: pointer;
        font-size: 13px;
        color: var(--_text-muted);
        user-select: none;
        padding: 6px 0;
        text-align: center;
        list-style: none;
      }
      details.alt-device summary::-webkit-details-marker { display: none; }
      details.alt-device summary::before {
        content: '\u25B8 ';
        display: inline-block;
        transition: transform 0.2s;
      }
      details.alt-device[open] summary::before { transform: rotate(90deg); }
      details.alt-device > .qr-frame { margin-top: 10px; }

      /* Footer */
      .footer {
        margin-top: 18px;
        font-size: 10px;
        color: #c4cdd5;
      }
      .footer a { color: var(--_disabled); text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `}_bindButtonEvents(){this.shadow.getElementById("open-btn")?.addEventListener("click",()=>{this._openModal(),this._startAuth()});let e=this.shadow.getElementById("overlay");e?.addEventListener("click",i=>{i.target===e&&this._closeModal()}),this._bindModalButtons()}_bindInlineEvents(){this.shadow.getElementById("start-btn")?.addEventListener("click",()=>{this._startAuth()})}_bindModalButtons(){this.shadow.getElementById("close-btn")?.addEventListener("click",()=>this._closeModal()),this.shadow.getElementById("retry-btn")?.addEventListener("click",()=>this._retry()),this.shadow.getElementById("mobile-cta")?.addEventListener("click",()=>this._openApprovalPage())}_openApprovalPage(){if(!this._sessionToken)return;let t=`${this.baseUrl}/a/${this._sessionToken}`;window.open(t,"_blank","noopener")||(window.location.href=t)}_openModal(){this.shadow.getElementById("overlay")?.classList.remove("hidden"),this._updateBody(this._bodyForStatus("idle"))}_closeModal(){this.shadow.getElementById("overlay")?.classList.add("hidden"),this._clearTimers(),this._sessionId=null,this._sessionToken=null,this._codeVerifier=null,this._status="idle",this._expiresAt=null}async _startAuth(){this._status="loading",this._updateBody(this._bodyForStatus("loading"));try{this._codeVerifier=await this.generateCodeVerifier();let t=await this.computeCodeChallenge(this._codeVerifier),e={"Content-Type":"application/json","X-Client-Id":this.tenant},i={scopes:this.scopes.split(/\s+/).filter(Boolean),codeChallenge:t,codeChallengeMethod:"S256"};this.redirectUri&&(i.redirectUrl=this.redirectUri);let r=await fetch(`${this.baseUrl}/api/v1/auth-sessions`,{method:"POST",headers:e,body:JSON.stringify(i)});if(!r.ok){let d=await r.json().catch(()=>({message:"Failed to create session"}));throw new Error(d.message??"Failed to create session")}let s=await r.json();this._sessionId=s.sessionId,this._sessionToken=s.token||(s.qrUrl?s.qrUrl.split("/").pop()??null:null),this._expiresAt=new Date(s.expiresAt).getTime(),this._status="pending",this._updateBody(this._bodyForStatus("pending",{qrUrl:s.qrUrl})),this._bindModalButtons(),this._startCountdown(),this._beginPolling(s.sessionId)}catch(t){let e=t instanceof Error?t.message:"Unexpected error";this._status="error",this._updateBody(this._bodyForStatus("error",{errorMessage:e})),this._bindModalButtons(),this.emit("qrauth:error",{message:e})}}_retry(){if(this._clearTimers(),this._sessionId=null,this._sessionToken=null,this._codeVerifier=null,this._status="idle",this._expiresAt=null,this.display==="inline"){let t=this.shadow.getElementById("inline-body");t&&(t.innerHTML=this._inlineIdleContent(),this._bindInlineEvents())}else this._startAuth()}_beginPolling(t){let e="PENDING",i=2e3,r=5e3,s=0,d=20,h=async()=>{if(!this._sessionId)return;let l=`${this.baseUrl}/api/v1/auth-sessions/${t}`;this._codeVerifier&&(l+=`?code_verifier=${encodeURIComponent(this._codeVerifier)}`);try{let c=await(await fetch(l,{headers:{"X-Client-Id":this.tenant}})).json();if(s=0,i=2e3,c.status!==e&&(e=c.status,this._handleStatusChange(c.status,c),["APPROVED","DENIED","EXPIRED"].includes(c.status)))return;this._pollTimeout=setTimeout(h,i)}catch{if(s++,s>=d){this._handleStatusChange("EXPIRED",void 0);return}i=Math.min(i*1.5,r),this._pollTimeout=setTimeout(h,i)}};this._pollTimeout=setTimeout(h,i)}_handleStatusChange(t,e){switch(this._status=t,t){case"SCANNED":{let i=this.shadow.querySelector(".qr-frame img")?.src,r=i?decodeURIComponent(i.replace(/.*[?&]data=/,"").split("&")[0]):"";this._updateBody(this._bodyForStatus("SCANNED",{qrUrl:r,timerHtml:this._formatTimer()})),this._bindModalButtons(),this.emit("qrauth:scanned",e);break}case"APPROVED":{this._clearTimers(),this._updateBody(this._bodyForStatus("APPROVED")),this._bindModalButtons(),this.emit("qrauth:authenticated",{sessionId:e?.sessionId,user:e?.user,signature:e?.signature});let i=this.onAuth;if(i){let r=window[i];typeof r=="function"&&r(e)}this.redirectUrl?setTimeout(()=>{window.location.href=this.redirectUrl},1500):this.display==="button"&&setTimeout(()=>this._closeModal(),2200);break}case"DENIED":this._clearTimers(),this._updateBody(this._bodyForStatus("DENIED")),this._bindModalButtons(),this.emit("qrauth:denied");break;case"EXPIRED":this._clearTimers(),this._status="EXPIRED",this._updateBody(this._bodyForStatus("EXPIRED")),this._bindModalButtons(),this.emit("qrauth:expired");break}}_startCountdown(){this._timerInterval=setInterval(()=>{let t=this.shadow.getElementById("timer");if(!t||!this._expiresAt)return;let e=Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3));t.textContent=e>0?this._formatTimer(e):"",e<=0&&(clearInterval(this._timerInterval),this._timerInterval=null,(this._status==="pending"||this._status==="SCANNED")&&this._handleStatusChange("EXPIRED",void 0))},1e3)}_formatTimer(t){let e=t??(this._expiresAt?Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3)):0),i=Math.floor(e/60),r=e%60;return`Expires in ${i}:${r<10?"0":""}${r}`}_updateBody(t){let e=this.display==="inline"?this.shadow.getElementById("inline-body"):this.shadow.getElementById("modal-body");e&&(e.innerHTML=t)}_clearTimers(){this._timerInterval&&(clearInterval(this._timerInterval),this._timerInterval=null),this._pollTimeout&&(clearTimeout(this._pollTimeout),this._pollTimeout=null)}};customElements.define("qrauth-login",g);var x=`<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z"
        fill="none" stroke="#fff" stroke-width="5"/>
  <g fill="#fff" opacity="0.2">
    <rect x="52" y="40" width="18" height="18" rx="3"/>
    <rect x="78" y="40" width="18" height="18" rx="3"/>
    <rect x="130" y="40" width="18" height="18" rx="3"/>
    <rect x="52" y="66" width="18" height="18" rx="3"/>
    <rect x="104" y="66" width="18" height="18" rx="3"/>
    <rect x="78" y="92" width="18" height="18" rx="3"/>
    <rect x="130" y="92" width="18" height="18" rx="3"/>
    <rect x="52" y="118" width="18" height="18" rx="3"/>
    <rect x="104" y="118" width="18" height="18" rx="3"/>
  </g>
  <path d="M62 104 L88 134 L144 64"
        fill="none" stroke="#fff" stroke-width="15"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`,R=`<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" fill="currentColor"/>
</svg>`,M=`<svg class="spinner" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2.5"
          stroke-dasharray="31.416" stroke-dashoffset="10" stroke-linecap="round"/>
</svg>`,b=class extends p{constructor(){super(...arguments);n(this,"_sessionId",null);n(this,"_claimUrl",null);n(this,"_status","idle");n(this,"_expiresAt",null);n(this,"_timerInterval",null);n(this,"_pollTimeout",null)}static get observedAttributes(){return[...super.observedAttributes,"scopes","ttl","max-uses","device-binding","display"]}get scopes(){return this.getAttribute("scopes")||"access"}get ttl(){return this.getAttribute("ttl")||"30m"}get maxUses(){return parseInt(this.getAttribute("max-uses")||"1",10)}get deviceBinding(){return this.hasAttribute("device-binding")}get display(){return this.getAttribute("display")||"inline"}get forceMode(){let t=this.getAttribute("force-mode");return t==="mobile"||t==="desktop"?t:"auto"}get mobileFallbackOnly(){return this.hasAttribute("mobile-fallback-only")}disconnectedCallback(){super.disconnectedCallback(),this._clearTimers()}render(){this.display==="button"?this._renderButton():this._renderInline()}_renderButton(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: inline-block; }

        .btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          user-select: none;
          line-height: 1.4;
          font-family: inherit;
        }
        .btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(27,42,74,0.3);
        }
        .btn:active:not(:disabled) { transform: translateY(0); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        /* Modal overlay */
        .overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.55);
          z-index: 99999;
          display: flex;
          align-items: center;
          justify-content: center;
          animation: fade-in 0.2s ease;
        }
        .overlay.hidden { display: none; }

        @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slide-up {
          from { transform: translateY(24px); opacity: 0; }
          to   { transform: translateY(0); opacity: 1; }
        }

        .modal {
          background: var(--_bg);
          border-radius: 16px;
          padding: 32px 28px 24px;
          max-width: 380px;
          width: 90vw;
          box-shadow: var(--_shadow);
          text-align: center;
          animation: slide-up 0.3s ease;
          position: relative;
        }

        ${this._sharedModalStyles()}
      </style>

      <button class="btn" id="open-btn" aria-label="Get access QR code">
        <span class="btn-icon">${x}</span>
        Get Access QR
      </button>

      <div class="overlay hidden" id="overlay" role="dialog" aria-modal="true" aria-label="QRAuth ephemeral access">
        <div class="modal">
          ${this._modalContent()}
        </div>
      </div>
    `,this._bindButtonEvents()}_renderInline(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: block; }

        .inline-container {
          background: var(--_bg);
          border: 1px solid var(--_border);
          border-radius: 16px;
          padding: 28px 24px 20px;
          text-align: center;
          max-width: 360px;
          margin: 0 auto;
        }

        /* Idle state: show start button */
        .start-btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: inherit;
          width: 100%;
          justify-content: center;
        }
        .start-btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
        }
        .start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        ${this._sharedModalStyles()}
      </style>

      <div class="inline-container">
        <div id="inline-body">
          ${this._inlineIdleContent()}
        </div>
      </div>
    `,this._bindInlineEvents()}_inlineIdleContent(){return`
      <button class="start-btn" id="start-btn" aria-label="Get access QR code">
        <span class="btn-icon">${x}</span>
        Get Access QR
      </button>
    `}_modalContent(){return`
      <button class="close-btn" id="close-btn" aria-label="Close">&times;</button>
      <div id="modal-body">
        ${this._bodyForStatus("idle")}
      </div>
    `}_bodyForStatus(t,e){switch(t){case"idle":return`
          <div class="state-header">
            <div class="brand-icon">${x}</div>
            <h3>Ephemeral Access</h3>
            <p>Scan to claim temporary access</p>
          </div>
        `;case"loading":return`
          <div class="state-loading">
            <div class="spinner-wrap">${M}</div>
            <p class="status-text">Generating access QR...</p>
          </div>
        `;case"active":{let i=e?.claimUrl?`https://api.qrserver.com/v1/create-qr-code/?size=440x440&data=${encodeURIComponent(e.claimUrl)}`:"",r=e?.useCount??0,s=e?.maxUses??1,h=s>1?`<div class="use-badge">${r}/${s} claimed</div>`:"";return`
          <h3>Scan to Access</h3>
          <p class="subtitle">Present this QR code to gain entry</p>
          <div class="qr-frame">
            <img src="${i}" alt="Ephemeral access QR code" width="220" height="220" loading="lazy"/>
            <div class="qr-badge">${x}</div>
          </div>
          ${h}
          <div class="timer" id="timer">${e?.timerHtml??""}</div>
          <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
        `}case"CLAIMED":return`
          <div class="state-claimed">
            <div class="success-icon">${R}</div>
            <h3>Access granted!</h3>
            <p class="subtitle">The QR code has been claimed successfully</p>
          </div>
        `;case"EXPIRED":return`
          <div class="state-expired">
            <div class="expired-icon">&#8987;</div>
            <h3>Access expired</h3>
            <p class="subtitle">This QR code has timed out.</p>
            <button class="retry-btn" id="retry-btn">Generate new QR</button>
          </div>
        `;case"REVOKED":return`
          <div class="state-revoked">
            <div class="error-icon">&#128683;</div>
            <h3>Access revoked</h3>
            <p class="subtitle">This ephemeral session has been revoked.</p>
          </div>
        `;case"error":return`
          <div class="state-error">
            <div class="error-icon">&#9888;</div>
            <h3>Something went wrong</h3>
            <p class="subtitle">${e?.errorMessage??"Failed to create ephemeral session."}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;default:return""}}_sharedModalStyles(){return`
      /* Typography */
      h3 {
        font-size: 18px;
        font-weight: 700;
        color: var(--_text);
        margin: 0 0 6px;
      }
      .subtitle {
        font-size: 13px;
        color: var(--_text-muted);
        margin: 0 0 20px;
        line-height: 1.5;
      }

      /* Close button */
      .close-btn {
        position: absolute;
        top: 12px;
        right: 14px;
        background: none;
        border: none;
        cursor: pointer;
        color: var(--_text-muted);
        font-size: 22px;
        line-height: 1;
        padding: 4px 6px;
        border-radius: 6px;
        transition: color 0.15s, background 0.15s;
        font-family: inherit;
      }
      .close-btn:hover { color: var(--_text); background: var(--_surface); }

      /* Brand icon in idle state */
      .state-header { padding: 8px 0 4px; }
      .brand-icon {
        width: 56px;
        height: 56px;
        background: var(--_btn-bg);
        border-radius: 14px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 14px;
        padding: 10px;
      }
      .brand-icon svg { width: 36px; height: 36px; }

      /* Loading state */
      .state-loading {
        padding: 32px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
      }
      .spinner-wrap { color: var(--_primary); }
      .spinner {
        width: 40px;
        height: 40px;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      /* QR frame */
      .qr-frame {
        display: inline-block;
        padding: 14px;
        background: #fff;
        border: 2px solid var(--_border);
        border-radius: var(--_radius);
        margin-bottom: 14px;
        position: relative;
        transition: border-color 0.3s;
      }
      .qr-frame img { display: block; width: 220px; height: 220px; border-radius: 4px; }
      .qr-badge {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 52px;
        height: 52px;
        background: #1b2a4a;
        border-radius: 10px;
        padding: 6px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .qr-badge svg { width: 100%; height: 100%; }

      /* Multi-use badge */
      .use-badge {
        display: inline-block;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 20px;
        padding: 4px 12px;
        font-size: 12px;
        font-weight: 600;
        color: var(--_text-muted);
        margin-bottom: 8px;
      }

      /* Status text */
      .status-text {
        font-size: 13px;
        color: var(--_text-muted);
        min-height: 20px;
      }

      /* Timer */
      .timer {
        font-size: 12px;
        color: var(--_disabled);
        margin-top: 8px;
        font-variant-numeric: tabular-nums;
        min-height: 18px;
      }

      /* Claimed / success state */
      .state-claimed {
        padding: 24px 0 12px;
        animation: fade-scale-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      }
      @keyframes fade-scale-in {
        from { transform: scale(0.85); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }
      .success-icon {
        width: 64px;
        height: 64px;
        background: var(--_success);
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        margin-bottom: 16px;
      }
      .success-icon svg { width: 36px; height: 36px; }

      /* Expired / revoked / error states */
      .state-expired, .state-revoked, .state-error {
        padding: 20px 0 8px;
      }
      .error-icon, .expired-icon {
        font-size: 48px;
        margin-bottom: 12px;
        line-height: 1;
        display: block;
      }
      .state-revoked .error-icon { color: var(--_error); }
      .state-expired .expired-icon { color: var(--_disabled); }
      .state-error .error-icon    { color: var(--_warning); }

      /* Retry button */
      .retry-btn {
        margin-top: 14px;
        padding: 9px 22px;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        color: var(--_text-muted);
        font-family: inherit;
        transition: background 0.15s, border-color 0.15s;
      }
      .retry-btn:hover { background: var(--_border); color: var(--_text); }

      /* Footer */
      .footer {
        margin-top: 18px;
        font-size: 10px;
        color: #c4cdd5;
      }
      .footer a { color: var(--_disabled); text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `}_bindButtonEvents(){this.shadow.getElementById("open-btn")?.addEventListener("click",()=>{this._openModal(),this._startSession()});let e=this.shadow.getElementById("overlay");e?.addEventListener("click",i=>{i.target===e&&this._closeModal()}),this._bindModalButtons()}_bindInlineEvents(){this.shadow.getElementById("start-btn")?.addEventListener("click",()=>{this._startSession()})}_bindModalButtons(){this.shadow.getElementById("close-btn")?.addEventListener("click",()=>this._closeModal()),this.shadow.getElementById("retry-btn")?.addEventListener("click",()=>this._retry())}_openModal(){this.shadow.getElementById("overlay")?.classList.remove("hidden"),this._updateBody(this._bodyForStatus("idle"))}_closeModal(){this.shadow.getElementById("overlay")?.classList.add("hidden"),this._clearTimers(),this._sessionId=null,this._claimUrl=null,this._status="idle",this._expiresAt=null}async _startSession(){this._status="loading",this._updateBody(this._bodyForStatus("loading"));try{let t=await fetch(`${this.baseUrl}/api/v1/ephemeral`,{method:"POST",headers:{"Content-Type":"application/json","X-Client-Id":this.tenant},body:JSON.stringify({scopes:this.scopes.split(/\s+/).filter(Boolean),ttl:this.ttl,maxUses:this.maxUses,deviceBinding:this.deviceBinding})});if(!t.ok){let i=await t.json().catch(()=>({message:"Failed to create session"}));throw new Error(i.message??"Failed to create session")}let e=await t.json();this._sessionId=e.sessionId,this._claimUrl=e.claimUrl,this._expiresAt=new Date(e.expiresAt).getTime(),this._status="active",this._updateBody(this._bodyForStatus("active",{claimUrl:e.claimUrl,timerHtml:this._formatTimer(),useCount:0,maxUses:e.maxUses})),this._bindModalButtons(),this._startCountdown(),this._beginPolling(e.sessionId)}catch(t){let e=t instanceof Error?t.message:"Unexpected error";this._status="error",this._updateBody(this._bodyForStatus("error",{errorMessage:e})),this._bindModalButtons(),this.emit("qrauth:error",{message:e})}}_retry(){if(this._clearTimers(),this._sessionId=null,this._claimUrl=null,this._status="idle",this._expiresAt=null,this.display==="inline"){let t=this.shadow.getElementById("inline-body");t&&(t.innerHTML=this._inlineIdleContent(),this._bindInlineEvents())}else this._startSession()}_beginPolling(t){let e=2e3,i=5e3,r=0,s=20,d=async()=>{if(this._sessionId)try{let l=await(await fetch(`${this.baseUrl}/api/v1/ephemeral/${t}`,{headers:{"X-Client-Id":this.tenant}})).json();if(r=0,e=2e3,this._handleStatusChange(l.status,l),["CLAIMED","EXPIRED","REVOKED"].includes(l.status)){if(l.status==="CLAIMED"&&l.useCount<l.maxUses){this._updateBody(this._bodyForStatus("active",{claimUrl:this._claimUrl??void 0,timerHtml:this._formatTimer(),useCount:l.useCount,maxUses:l.maxUses})),this._bindModalButtons(),this._pollTimeout=setTimeout(d,e);return}return}this._pollTimeout=setTimeout(d,e)}catch{if(r++,r>=s){this._handleStatusChange("EXPIRED",void 0);return}e=Math.min(e*1.5,i),this._pollTimeout=setTimeout(d,e)}};this._pollTimeout=setTimeout(d,e)}_handleStatusChange(t,e){switch(t){case"CLAIMED":{this._clearTimers(),this._status="CLAIMED",this._updateBody(this._bodyForStatus("CLAIMED")),this._bindModalButtons(),this.emit("qrauth:claimed",{sessionId:e?.sessionId,status:e?.status,scopes:e?.scopes,metadata:e?.metadata,useCount:e?.useCount,maxUses:e?.maxUses}),this.display==="button"&&setTimeout(()=>this._closeModal(),2200);break}case"EXPIRED":this._clearTimers(),this._status="EXPIRED",this._updateBody(this._bodyForStatus("EXPIRED")),this._bindModalButtons(),this.emit("qrauth:expired");break;case"REVOKED":this._clearTimers(),this._status="REVOKED",this._updateBody(this._bodyForStatus("REVOKED")),this._bindModalButtons(),this.emit("qrauth:revoked");break}}_startCountdown(){this._timerInterval=setInterval(()=>{let t=this.shadow.getElementById("timer");if(!t||!this._expiresAt)return;let e=Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3));t.textContent=e>0?this._formatTimer(e):"",e<=0&&(clearInterval(this._timerInterval),this._timerInterval=null,this._status==="active"&&this._handleStatusChange("EXPIRED",void 0))},1e3)}_formatTimer(t){let e=t??(this._expiresAt?Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3)):0),i=Math.floor(e/60),r=e%60;return`Expires in ${i}:${r<10?"0":""}${r}`}_updateBody(t){let e=this.display==="inline"?this.shadow.getElementById("inline-body"):this.shadow.getElementById("modal-body");e&&(e.innerHTML=t)}_clearTimers(){this._timerInterval&&(clearInterval(this._timerInterval),this._timerInterval=null),this._pollTimeout&&(clearTimeout(this._pollTimeout),this._pollTimeout=null)}};customElements.define("qrauth-ephemeral",b);var f=`<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z"
        fill="none" stroke="#fff" stroke-width="5"/>
  <g fill="#fff" opacity="0.2">
    <rect x="52" y="40" width="18" height="18" rx="3"/>
    <rect x="78" y="40" width="18" height="18" rx="3"/>
    <rect x="130" y="40" width="18" height="18" rx="3"/>
    <rect x="52" y="66" width="18" height="18" rx="3"/>
    <rect x="104" y="66" width="18" height="18" rx="3"/>
    <rect x="78" y="92" width="18" height="18" rx="3"/>
    <rect x="130" y="92" width="18" height="18" rx="3"/>
    <rect x="52" y="118" width="18" height="18" rx="3"/>
    <rect x="104" y="118" width="18" height="18" rx="3"/>
  </g>
  <path d="M62 104 L88 134 L144 64"
        fill="none" stroke="#fff" stroke-width="15"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`,y=`<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" fill="currentColor"/>
</svg>`,q=`<svg class="spinner" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2.5"
          stroke-dasharray="31.416" stroke-dashoffset="10" stroke-linecap="round"/>
</svg>`,m=class extends p{constructor(){super(...arguments);n(this,"_sessionId",null);n(this,"_sessionToken",null);n(this,"_codeVerifier",null);n(this,"_status","idle");n(this,"_expiresAt",null);n(this,"_timerInterval",null);n(this,"_pollTimeout",null)}static get observedAttributes(){return[...super.observedAttributes,"session-token","scopes","auto-start","redirect-uri"]}get sessionToken(){return this.getAttribute("session-token")}get scopes(){return this.getAttribute("scopes")||"identity"}get autoStart(){return this.hasAttribute("auto-start")}get redirectUri(){return this.getAttribute("redirect-uri")}get forceMode(){let t=this.getAttribute("force-mode");return t==="mobile"||t==="desktop"?t:"auto"}get mobileFallbackOnly(){return this.hasAttribute("mobile-fallback-only")}connectedCallback(){super.connectedCallback(),this.autoStart&&this._startAuth()}disconnectedCallback(){super.disconnectedCallback(),this._clearTimers()}render(){this.shadow.innerHTML=`
      <style>
        ${this.getBaseStyles()}
        :host { display: block; }

        .container {
          background: var(--_bg);
          border: 1px solid var(--_border);
          border-radius: 16px;
          padding: 24px 20px 18px;
          text-align: center;
          max-width: 320px;
          margin: 0 auto;
          box-shadow: 0 2px 12px rgba(0,0,0,0.06);
        }

        /* Step indicator */
        .step-label {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.06em;
          text-transform: uppercase;
          color: var(--_primary);
          background: rgba(0,167,111,0.08);
          border-radius: 20px;
          padding: 4px 10px;
          margin-bottom: 14px;
        }
        .step-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: var(--_primary);
          flex-shrink: 0;
        }

        /* Idle start button */
        .start-btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 11px 22px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: inherit;
          width: 100%;
          justify-content: center;
          margin-top: 4px;
        }
        .start-btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(27,42,74,0.3);
        }
        .start-btn:active:not(:disabled) { transform: translateY(0); }
        .start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 20px; height: 20px; flex-shrink: 0; }

        ${this._sharedStyles()}
      </style>

      <div class="container" role="region" aria-label="Second-factor authentication">
        <div id="body">
          ${this._bodyForStatus("idle")}
        </div>
      </div>
    `,this._bindBodyEvents()}_bodyForStatus(t,e){let i=`
      <div class="step-label">
        <span class="step-dot"></span>
        Step 2 of 2 &mdash; Verify identity
      </div>
    `;switch(t){case"idle":return`
          ${i}
          <div class="state-header">
            <div class="brand-icon">${f}</div>
            <h3>Verify your identity</h3>
            <p class="subtitle">Scan the QR code with your phone to confirm it&apos;s you</p>
          </div>
          <button class="start-btn" id="start-btn" aria-label="Start 2FA verification">
            <span class="btn-icon">${f}</span>
            Verify your identity
          </button>
        `;case"loading":return`
          ${i}
          <div class="state-loading">
            <div class="spinner-wrap">${q}</div>
            <p class="status-text">Generating QR code...</p>
          </div>
        `;case"pending":case"SCANNED":{if(this.isMobileLike())return this._mobilePendingBody(t,e,i);let r=t==="SCANNED";return`
          ${i}
          <h3>Scan to verify</h3>
          <p class="subtitle">Use your phone camera to complete verification</p>
          ${this._qrFrameHtml(e?.qrUrl??"",r)}
          <div class="status-text ${r?"status-scanned":""}">
            ${r?"&#10003; Scanned &mdash; waiting for approval...":"Waiting for scan..."}
          </div>
          <div class="timer" id="timer">${e?.timerHtml??""}</div>
          <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
        `}case"APPROVED":return`
          <div class="state-approved">
            <div class="success-icon">${y}</div>
            <h3>Identity verified!</h3>
            <p class="subtitle">Second factor confirmed</p>
          </div>
        `;case"DENIED":return`
          <div class="state-denied">
            <div class="error-icon">&#10007;</div>
            <h3>Verification denied</h3>
            <p class="subtitle">The request was declined on your device.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;case"EXPIRED":return`
          <div class="state-expired">
            <div class="expired-icon">&#8987;</div>
            <h3>Session expired</h3>
            <p class="subtitle">The QR code has timed out.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;case"error":return`
          <div class="state-error">
            <div class="error-icon">&#9888;</div>
            <h3>Something went wrong</h3>
            <p class="subtitle">${e?.errorMessage??"Failed to start verification."}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;default:return""}}_qrFrameHtml(t,e){let i=t?`https://api.qrserver.com/v1/create-qr-code/?size=320x320&data=${encodeURIComponent(t)}`:"";return`
      <div class="qr-frame ${e?"scanned":""}">
        <img src="${i}" alt="QR Code for 2FA verification" width="160" height="160" loading="lazy"/>
        <div class="qr-badge">${f}</div>
        ${e?'<div class="scanned-overlay"><span class="scanned-check">'+y+"</span></div>":""}
      </div>
    `}_mobilePendingBody(t,e,i=""){let r=t==="SCANNED";return`
      ${i}
      <h3>Verify your identity</h3>
      <p class="subtitle">Tap continue to verify on this device.</p>
      <button class="mobile-cta" id="mobile-cta" type="button">
        <span class="btn-icon">${f}</span>
        Continue with QRAuth
      </button>
      <div class="status-text ${r?"status-scanned":""}">
        ${r?"&#10003; Scanned &mdash; waiting for approval...":"Waiting for approval..."}
      </div>
      <div class="timer" id="timer">${e?.timerHtml??""}</div>
      <details class="alt-device">
        <summary>Use another device</summary>
        ${this._qrFrameHtml(e?.qrUrl??"",r)}
      </details>
      <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
    `}_sharedStyles(){return`
      /* Typography */
      h3 {
        font-size: 16px;
        font-weight: 700;
        color: var(--_text);
        margin: 0 0 5px;
      }
      .subtitle {
        font-size: 12px;
        color: var(--_text-muted);
        margin: 0 0 16px;
        line-height: 1.5;
      }

      /* Brand icon in idle state */
      .state-header { padding: 4px 0 2px; }
      .brand-icon {
        width: 48px;
        height: 48px;
        background: var(--_btn-bg);
        border-radius: 12px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 12px;
        padding: 8px;
      }
      .brand-icon svg { width: 32px; height: 32px; }

      /* Loading state */
      .state-loading {
        padding: 24px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 14px;
      }
      .spinner-wrap { color: var(--_primary); }
      .spinner {
        width: 36px;
        height: 36px;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      /* QR frame \u2014 compact 160x160 */
      .qr-frame {
        display: inline-block;
        padding: 10px;
        background: #fff;
        border: 2px solid var(--_border);
        border-radius: var(--_radius);
        margin-bottom: 12px;
        position: relative;
        transition: border-color 0.3s;
      }
      .qr-frame.scanned { border-color: var(--_success); }
      .qr-frame img { display: block; width: 160px; height: 160px; border-radius: 4px; }

      /* Smaller badge for compact QR */
      .qr-badge {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 40px;
        height: 40px;
        background: #1b2a4a;
        border-radius: 8px;
        padding: 5px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .qr-badge svg { width: 100%; height: 100%; }

      /* Scanned overlay on QR */
      .scanned-overlay {
        position: absolute;
        inset: 0;
        background: rgba(0,167,111,0.08);
        border-radius: calc(var(--_radius) - 2px);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .scanned-check {
        width: 40px;
        height: 40px;
        background: var(--_success);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        opacity: 0;
        animation: pop-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.1s forwards;
      }
      .scanned-check svg { width: 22px; height: 22px; }
      @keyframes pop-in {
        from { transform: scale(0.5); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }

      /* Status text */
      .status-text {
        font-size: 12px;
        color: var(--_text-muted);
        min-height: 18px;
      }
      .status-scanned {
        color: var(--_success);
        font-weight: 600;
      }

      /* Timer */
      .timer {
        font-size: 11px;
        color: var(--_disabled);
        margin-top: 6px;
        font-variant-numeric: tabular-nums;
        min-height: 16px;
      }

      /* Success state */
      .state-approved {
        padding: 16px 0 8px;
        animation: fade-scale-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      }
      @keyframes fade-scale-in {
        from { transform: scale(0.85); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }
      .success-icon {
        width: 56px;
        height: 56px;
        background: var(--_success);
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        margin-bottom: 14px;
      }
      .success-icon svg { width: 30px; height: 30px; }

      /* Denied / expired / error states */
      .state-denied, .state-expired, .state-error {
        padding: 16px 0 6px;
      }
      .error-icon, .expired-icon {
        font-size: 40px;
        margin-bottom: 10px;
        line-height: 1;
        display: block;
      }
      .state-denied .error-icon    { color: var(--_error); }
      .state-expired .expired-icon { color: var(--_disabled); }
      .state-error .error-icon     { color: var(--_warning); }

      /* Retry button */
      .retry-btn {
        margin-top: 12px;
        padding: 8px 20px;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 8px;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        color: var(--_text-muted);
        font-family: inherit;
        transition: background 0.15s, border-color 0.15s;
      }
      .retry-btn:hover { background: var(--_border); color: var(--_text); }

      /* Mobile-aware pending state: primary CTA + QR expander */
      .mobile-cta {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        width: 100%;
        padding: 12px 18px;
        background: var(--_btn-bg);
        color: #fff;
        border: none;
        border-radius: var(--_radius);
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        font-family: inherit;
        margin-bottom: 12px;
      }
      .mobile-cta:hover { background: var(--_btn-hover); }
      .mobile-cta .btn-icon { width: 18px; height: 18px; }

      details.alt-device {
        margin-top: 12px;
        text-align: left;
        border-top: 1px solid var(--_border);
        padding-top: 10px;
      }
      details.alt-device summary {
        cursor: pointer;
        font-size: 12px;
        color: var(--_text-muted);
        user-select: none;
        padding: 4px 0;
        text-align: center;
        list-style: none;
      }
      details.alt-device summary::-webkit-details-marker { display: none; }
      details.alt-device summary::before {
        content: '\u25B8 ';
        display: inline-block;
        transition: transform 0.2s;
      }
      details.alt-device[open] summary::before { transform: rotate(90deg); }
      details.alt-device > .qr-frame { margin-top: 8px; }

      /* Footer */
      .footer {
        margin-top: 14px;
        font-size: 10px;
        color: #c4cdd5;
      }
      .footer a { color: var(--_disabled); text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `}_bindBodyEvents(){this.shadow.getElementById("start-btn")?.addEventListener("click",()=>this._startAuth()),this.shadow.getElementById("retry-btn")?.addEventListener("click",()=>this._retry()),this.shadow.getElementById("mobile-cta")?.addEventListener("click",()=>this._openApprovalPage())}_openApprovalPage(){if(!this._sessionToken)return;let t=`${this.baseUrl}/a/${this._sessionToken}`;window.open(t,"_blank","noopener")||(window.location.href=t)}async _startAuth(){this._status="loading",this._updateBody(this._bodyForStatus("loading"));try{this._codeVerifier=await this.generateCodeVerifier();let t=await this.computeCodeChallenge(this._codeVerifier),e={"Content-Type":"application/json","X-Client-Id":this.tenant},i={scopes:this.scopes.split(/\s+/).filter(Boolean),codeChallenge:t,codeChallengeMethod:"S256"};this.redirectUri&&(i.redirectUrl=this.redirectUri);let r=await fetch(`${this.baseUrl}/api/v1/auth-sessions`,{method:"POST",headers:e,body:JSON.stringify(i)});if(!r.ok){let d=await r.json().catch(()=>({message:"Failed to create session"}));throw new Error(d.message??"Failed to create session")}let s=await r.json();this._sessionId=s.sessionId,this._sessionToken=s.token||(s.qrUrl?s.qrUrl.split("/").pop()??null:null),this._expiresAt=new Date(s.expiresAt).getTime(),this._status="pending",this._updateBody(this._bodyForStatus("pending",{qrUrl:s.qrUrl})),this._bindBodyEvents(),this._startCountdown(),this._beginPolling(s.sessionId)}catch(t){let e=t instanceof Error?t.message:"Unexpected error";this._status="error",this._updateBody(this._bodyForStatus("error",{errorMessage:e})),this._bindBodyEvents(),this.emit("qrauth:error",{message:e})}}_retry(){this._clearTimers(),this._sessionId=null,this._sessionToken=null,this._codeVerifier=null,this._status="idle",this._expiresAt=null,this._updateBody(this._bodyForStatus("idle")),this._bindBodyEvents()}_beginPolling(t){let e="PENDING",i=2e3,r=5e3,s=0,d=20,h=async()=>{if(!this._sessionId)return;let l=`${this.baseUrl}/api/v1/auth-sessions/${t}`;this._codeVerifier&&(l+=`?code_verifier=${encodeURIComponent(this._codeVerifier)}`);try{let c=await(await fetch(l,{headers:{"X-Client-Id":this.tenant}})).json();if(s=0,i=2e3,c.status!==e&&(e=c.status,this._handleStatusChange(c.status,c),["APPROVED","DENIED","EXPIRED"].includes(c.status)))return;this._pollTimeout=setTimeout(h,i)}catch{if(s++,s>=d){this._handleStatusChange("EXPIRED",void 0);return}i=Math.min(i*1.5,r),this._pollTimeout=setTimeout(h,i)}};this._pollTimeout=setTimeout(h,i)}_handleStatusChange(t,e){switch(this._status=t,t){case"SCANNED":{let i=this.shadow.querySelector(".qr-frame img")?.src,r=i?decodeURIComponent(i.replace(/.*[?&]data=/,"").split("&")[0]):"";this._updateBody(this._bodyForStatus("SCANNED",{qrUrl:r,timerHtml:this._formatTimer()})),this._bindBodyEvents();break}case"APPROVED":{this._clearTimers(),this._updateBody(this._bodyForStatus("APPROVED")),this.emit("qrauth:verified",{sessionId:e?.sessionId,user:e?.user,signature:e?.signature});break}case"DENIED":this._clearTimers(),this._updateBody(this._bodyForStatus("DENIED")),this._bindBodyEvents(),this.emit("qrauth:denied");break;case"EXPIRED":this._clearTimers(),this._status="EXPIRED",this._updateBody(this._bodyForStatus("EXPIRED")),this._bindBodyEvents(),this.emit("qrauth:expired");break}}_startCountdown(){this._timerInterval=setInterval(()=>{let t=this.shadow.getElementById("timer");if(!t||!this._expiresAt)return;let e=Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3));t.textContent=e>0?this._formatTimer(e):"",e<=0&&(clearInterval(this._timerInterval),this._timerInterval=null,(this._status==="pending"||this._status==="SCANNED")&&this._handleStatusChange("EXPIRED",void 0))},1e3)}_formatTimer(t){let e=t??(this._expiresAt?Math.max(0,Math.floor((this._expiresAt-Date.now())/1e3)):0),i=Math.floor(e/60),r=e%60;return`Expires in ${i}:${r<10?"0":""}${r}`}_updateBody(t){let e=this.shadow.getElementById("body");e&&(e.innerHTML=t)}_clearTimers(){this._timerInterval&&(clearInterval(this._timerInterval),this._timerInterval=null),this._pollTimeout&&(clearTimeout(this._pollTimeout),this._pollTimeout=null)}};customElements.define("qrauth-2fa",m);return C($);})();
//# sourceMappingURL=qrauth-components.js.map
