import Box from '@mui/material/Box';

import { paths } from 'src/routes/paths';
import { RouterLink } from 'src/routes/components';

// Logo component using the proper SVG logo
function QRAuthLogo({ size = 32 }: { size?: number }) {
  return <Box component="img" src="/logo.svg" alt="QRAuth" sx={{ width: size, height: size }} />;
}

// Inline style constants matching the HTML source CSS variables
const C = {
  navy: '#081b4c',
  navyLight: '#0c2461',
  navyLighter: '#102d6e',
  blueAccent: '#3B82F6',
  blueGlow: '#60A5FA',
  green: '#34D399',
  greenDark: '#10B981',
  greenGlow: 'rgba(52, 211, 153, 0.15)',
  white: '#F8FAFC',
  gray100: '#E2E8F0',
  gray200: '#CBD5E1',
  gray300: '#94A3B8',
  gray400: '#64748B',
  gray500: '#475569',
  red: '#EF4444',
  font: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
  mono: "'JetBrains Mono', 'Fira Code', monospace",
};

export default function HomePage() {
  return (
    <Box
      sx={{
        fontFamily: C.font,
        background: C.navy,
        color: C.white,
        lineHeight: 1.6,
        overflowX: 'hidden',
        minHeight: '100vh',
      }}
    >
      {/* Global style block for font import, CSS vars, and media queries */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

        .hp-nav-links { display: flex; align-items: center; gap: 32px; list-style: none; }
        .hp-hero-code { display: block; }
        .hp-fraud-visual { display: block; }
        .hp-hero { grid-template-columns: 1fr 1fr !important; }
        .hp-problem-grid { grid-template-columns: 1fr 1fr !important; }
        .hp-steps { grid-template-columns: repeat(3, 1fr) !important; }
        .hp-tiers { grid-template-columns: repeat(4, 1fr) !important; }
        .hp-features-grid { grid-template-columns: repeat(3, 1fr) !important; }
        .hp-protocol-grid { grid-template-columns: 1fr 1fr !important; }

        @media (max-width: 900px) {
          .hp-hero { grid-template-columns: 1fr !important; padding-top: 40px !important; }
          .hp-hero-h1 { font-size: 36px !important; }
          .hp-hero-code { display: none !important; }
          .hp-problem-grid { grid-template-columns: 1fr !important; }
          .hp-fraud-visual { display: none !important; }
          .hp-steps { grid-template-columns: 1fr !important; }
          .hp-tiers { grid-template-columns: 1fr 1fr !important; }
          .hp-features-grid { grid-template-columns: 1fr !important; }
          .hp-protocol-grid { grid-template-columns: 1fr !important; }
          .hp-nav-links { display: none !important; }
          .hp-cta-h2 { font-size: 32px !important; }
        }

        .hp-step:hover { border-color: rgba(52, 211, 153, 0.2) !important; transform: translateY(-4px); }
        .hp-tier:hover { border-color: rgba(52, 211, 153, 0.2) !important; transform: translateY(-4px); }
        .hp-feature:hover { border-color: rgba(59, 130, 246, 0.2) !important; }
        .hp-nav-link:hover { color: #F8FAFC !important; }
        .hp-nav-cta:hover { background: #10B981 !important; transform: translateY(-1px); }
        .hp-btn-primary:hover { background: #10B981 !important; transform: translateY(-1px); box-shadow: 0 8px 30px rgba(52, 211, 153, 0.25) !important; }
        .hp-btn-secondary:hover { border-color: rgba(255,255,255,0.3) !important; background: rgba(255,255,255,0.05) !important; }
        .hp-copy-btn:hover { color: #F8FAFC !important; }
        .hp-footer-link:hover { color: #CBD5E1 !important; }
      `}</style>

      {/* ================================================================ */}
      {/* NAV */}
      {/* ================================================================ */}
      <nav style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: 1200, margin: '0 auto', padding: '20px 32px' }}>
        <a
          href="#"
          style={{ display: 'flex', alignItems: 'center', gap: 10, fontWeight: 800, fontSize: 20, letterSpacing: '-0.5px', textDecoration: 'none', color: C.white, fontFamily: C.font }}
        >
          <QRAuthLogo size={32} />
          QRAuth
        </a>

        <ul className="hp-nav-links">
          {(['Docs', 'SDKs', 'Pricing', 'Protocol', 'Blog'] as const).map((label) => (
            <li key={label}>
              <a
                href="#"
                className="hp-nav-link"
                style={{ color: C.gray300, textDecoration: 'none', fontSize: 14, fontWeight: 500, transition: 'color 0.2s', fontFamily: C.font }}
              >
                {label}
              </a>
            </li>
          ))}
        </ul>

        <RouterLink
          href={paths.auth.jwt.signUp}
          className="hp-nav-cta"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: C.green, color: C.navy, padding: '8px 20px', borderRadius: 8, fontSize: 14, fontWeight: 600, textDecoration: 'none', transition: 'background 0.2s, transform 0.1s', fontFamily: C.font }}
        >
          Get API Key &rarr;
        </RouterLink>
      </nav>

      {/* ================================================================ */}
      {/* HERO */}
      {/* ================================================================ */}
      <section
        className="hp-hero"
        style={{ maxWidth: 1200, margin: '0 auto', padding: '80px 32px 60px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 64, alignItems: 'center' }}
      >
        {/* Left: content */}
        <div>
          <h1
            className="hp-hero-h1"
            style={{ fontSize: 52, fontWeight: 800, lineHeight: 1.1, letterSpacing: '-1.5px', marginBottom: 24, fontFamily: C.font, color: C.white }}
          >
            Stop QR code fraud.<br />
            <span style={{ background: `linear-gradient(135deg, ${C.green}, ${C.blueGlow})`, WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
              Verify every scan.
            </span>
          </h1>
          <p style={{ fontSize: 18, color: C.gray300, lineHeight: 1.7, marginBottom: 32, maxWidth: 500, fontFamily: C.font }}>
            QRAuth is the authentication infrastructure for physical QR codes. Add cryptographic verification, geospatial binding, and anti-phishing protection to any QR code with a few lines of code.
          </p>

          <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 40 }}>
            <RouterLink
              href={paths.auth.jwt.signUp}
              className="hp-btn-primary"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: C.green, color: C.navy, padding: '14px 28px', borderRadius: 10, fontSize: 16, fontWeight: 700, textDecoration: 'none', transition: 'all 0.2s', border: 'none', cursor: 'pointer', fontFamily: C.font }}
            >
              Start Building &rarr;
            </RouterLink>
            <a
              href="#"
              className="hp-btn-secondary"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'transparent', color: C.gray200, padding: '14px 28px', borderRadius: 10, fontSize: 16, fontWeight: 600, textDecoration: 'none', border: '1px solid rgba(255,255,255,0.15)', transition: 'all 0.2s', fontFamily: C.font }}
            >
              View Documentation
            </a>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 10, padding: '12px 20px', maxWidth: 400 }}>
            <code style={{ fontFamily: C.mono, fontSize: 14, color: C.green, flex: 1 }}>
              $ npm install @qrauth/node
            </code>
            <button
              className="hp-copy-btn"
              title="Copy"
              onClick={() => navigator.clipboard?.writeText('npm install @qrauth/node')}
              style={{ background: 'none', border: 'none', color: C.gray400, cursor: 'pointer', padding: 4, transition: 'color 0.2s', fontSize: 14 }}
            >
              &#x2398;
            </button>
          </div>
        </div>

        {/* Right: code block */}
        <div
          className="hp-hero-code"
          style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 16, overflow: 'hidden', boxShadow: '0 25px 60px rgba(0,0,0,0.4)' }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '14px 20px', background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#EF4444', display: 'inline-block' }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#F59E0B', display: 'inline-block' }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#22C55E', display: 'inline-block' }} />
            <span style={{ marginLeft: 12, fontFamily: C.mono, fontSize: 12, color: C.gray400 }}>app.ts</span>
          </div>
          <div
            style={{ padding: 24, fontFamily: C.mono, fontSize: 13, lineHeight: 1.8, overflowX: 'auto' }}
            dangerouslySetInnerHTML={{ __html: `<span style="color:#C084FC">import</span> { <span style="color:#67E8F9">QRAuth</span> } <span style="color:#C084FC">from</span> <span style="color:#34D399">'@qrauth/node'</span>;
<br><br>
<span style="color:#C084FC">const</span> <span style="color:#60A5FA">qrauth</span> = <span style="color:#C084FC">new</span> <span style="color:#67E8F9">QRAuth</span>({
<br>&nbsp;&nbsp;<span style="color:#93C5FD">tenantId</span>: <span style="color:#34D399">'parking-thessaloniki'</span>,
<br>&nbsp;&nbsp;<span style="color:#93C5FD">apiKey</span>: process.env.<span style="color:#93C5FD">QRAUTH_API_KEY</span>,
<br>});
<br><br>
<span style="color:#64748B">// Generate a verified QR code</span>
<br><span style="color:#C084FC">const</span> <span style="color:#60A5FA">qr</span> = <span style="color:#C084FC">await</span> qrauth.<span style="color:#60A5FA">create</span>({
<br>&nbsp;&nbsp;<span style="color:#93C5FD">destination</span>: <span style="color:#34D399">'https://parking.gr/pay'</span>,
<br>&nbsp;&nbsp;<span style="color:#93C5FD">location</span>: { <span style="color:#93C5FD">lat</span>: <span style="color:#F59E0B">40.63</span>, <span style="color:#93C5FD">lng</span>: <span style="color:#F59E0B">22.94</span> },
<br>&nbsp;&nbsp;<span style="color:#93C5FD">expiresIn</span>: <span style="color:#34D399">'1y'</span>,
<br>});
<br><br>
<span style="color:#64748B">// Verify a scanned QR code</span>
<br><span style="color:#C084FC">const</span> <span style="color:#60A5FA">result</span> = <span style="color:#C084FC">await</span> qrauth.<span style="color:#60A5FA">verify</span>(<span style="color:#34D399">'xK9m2pQ7'</span>);
<br><span style="color:#64748B">// { verified: true, trustScore: 94 }</span>` }}
          />
        </div>
      </section>

      {/* ================================================================ */}
      {/* TRUST BAR */}
      {/* ================================================================ */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '60px 32px', textAlign: 'center' }}>
        <p style={{ fontSize: 13, textTransform: 'uppercase', letterSpacing: 2, color: C.gray400, marginBottom: 32, fontWeight: 600, fontFamily: C.font }}>
          Built for companies securing physical QR codes
        </p>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 48, flexWrap: 'wrap', opacity: 0.4 }}>
          {['Parking Operators', 'Transit Agencies', 'Event Ticketing', 'Hospitality', 'Retail'].map((name) => (
            <span key={name} style={{ fontSize: 18, fontWeight: 700, color: C.gray200, letterSpacing: '-0.5px', fontFamily: C.font }}>
              {name}
            </span>
          ))}
        </div>
      </div>

      {/* Divider */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 32px' }}>
        <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.06)' }} />
      </div>

      {/* ================================================================ */}
      {/* PROBLEM */}
      {/* ================================================================ */}
      <section style={{ maxWidth: 1200, margin: '0 auto', padding: '80px 32px' }}>
        <div
          className="hp-problem-grid"
          style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 64, alignItems: 'center' }}
        >
          {/* Left: content */}
          <div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', color: '#FCA5A5', padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 24, fontFamily: C.font }}>
              &#9888; The Problem
            </div>
            <h2 style={{ fontSize: 40, fontWeight: 800, lineHeight: 1.15, letterSpacing: '-1px', marginBottom: 20, color: C.white, fontFamily: C.font }}>
              QR codes have zero built-in security
            </h2>
            <p style={{ fontSize: 17, color: C.gray300, lineHeight: 1.7, marginBottom: 24, fontFamily: C.font }}>
              Anyone with a printer can paste a fake QR code over a legitimate one. Victims scan it, land on a phishing site, and lose their payment credentials. There is no way to tell if a physical QR code is authentic.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
              {[
                { number: '$10B', label: 'Annual losses from QR/ticket fraud' },
                { number: '5M', label: 'Fake tickets purchased annually' },
                { number: '651', label: 'Arrests in INTERPOL Op Red Card 2.0' },
                { number: '38%', label: 'Surge in UK ticket fraud (2022-2024)' },
              ].map(({ number, label }) => (
                <div key={number} style={{ background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.1)', borderRadius: 12, padding: 20 }}>
                  <div style={{ fontSize: 28, fontWeight: 800, color: '#FCA5A5', marginBottom: 4, fontFamily: C.font }}>{number}</div>
                  <div style={{ fontSize: 13, color: C.gray400, lineHeight: 1.4, fontFamily: C.font }}>{label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Right: fraud visual */}
          <div className="hp-fraud-visual">
            <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 16, padding: 32 }}>
              <div style={{ width: 180, height: 180, background: 'white', borderRadius: 12, margin: '0 auto 24px', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
                {/* QR grid pattern */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 3, width: 120, height: 120 }}>
                  {[
                    1,1,1,1,1,0,1,
                    1,0,0,0,1,0,1,
                    1,0,1,0,1,0,0,
                    1,0,1,0,1,0,1,
                    1,0,0,0,1,0,1,
                    0,0,1,0,0,1,0,
                    1,1,1,1,1,0,1,
                  ].map((cell, i) => (
                    <div key={i} style={{ borderRadius: 2, background: cell ? C.navy : 'transparent' }} />
                  ))}
                </div>
                {/* Fraud overlay */}
                <div style={{ position: 'absolute', top: -12, right: -12, background: C.red, color: 'white', width: 44, height: 44, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20, fontWeight: 800, boxShadow: '0 4px 15px rgba(239, 68, 68, 0.4)', fontFamily: C.font }}>
                  !
                </div>
              </div>
              <div style={{ textAlign: 'center', fontFamily: C.mono, fontSize: 14, padding: '10px 16px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: 8, color: '#FCA5A5' }}>
                <span style={{ color: C.red, fontWeight: 700, textDecoration: 'line-through' }}>parkng-thessaloniki.gr</span>/pay
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Divider */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 32px' }}>
        <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.06)' }} />
      </div>

      {/* ================================================================ */}
      {/* SOLUTION */}
      {/* ================================================================ */}
      <section style={{ maxWidth: 1200, margin: '0 auto', padding: '100px 32px' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: C.greenGlow, border: '1px solid rgba(52, 211, 153, 0.2)', color: C.green, padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 24, fontFamily: C.font }}>
          &#10003; The Solution
        </div>
        <h2 style={{ fontSize: 40, fontWeight: 800, lineHeight: 1.15, letterSpacing: '-1px', marginBottom: 16, color: C.white, fontFamily: C.font }}>
          Three lines of code. Fully verified.
        </h2>
        <p style={{ fontSize: 18, color: C.gray300, maxWidth: 600, marginBottom: 64, lineHeight: 1.7, fontFamily: C.font }}>
          Integrate QRAuth into your application in minutes. Every QR code you generate is cryptographically signed, geospatially bound, and verifiable by anyone with a phone camera.
        </p>

        <div
          className="hp-steps"
          style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 32 }}
        >
          {[
            {
              num: '1',
              title: 'Install the SDK',
              body: (
                <>
                  Add <code style={{ fontFamily: C.mono, fontSize: 12, background: 'rgba(0,0,0,0.3)', padding: '2px 8px', borderRadius: 4, color: C.green }}>@qrauth/node</code> to your project. Available for Node.js, Python, Go, PHP, Swift, and Kotlin. Get your API key in 30 seconds.
                </>
              ),
            },
            {
              num: '2',
              title: 'Generate signed QR codes',
              body: (
                <>
                  Call <code style={{ fontFamily: C.mono, fontSize: 12, background: 'rgba(0,0,0,0.3)', padding: '2px 8px', borderRadius: 4, color: C.green }}>qrauth.create()</code> with your destination URL and physical location. We sign it with ECDSA-P256 and register it in the transparency log.
                </>
              ),
            },
            {
              num: '3',
              title: 'Users scan and verify',
              body: (
                <>
                  Scanners see a verified issuer badge — no app install needed. Embed our widget in your app, or let users verify at <code style={{ fontFamily: C.mono, fontSize: 12, background: 'rgba(0,0,0,0.3)', padding: '2px 8px', borderRadius: 4, color: C.green }}>qrauth.io/v/token</code>.
                </>
              ),
            },
          ].map(({ num, title, body }) => (
            <div
              key={num}
              className="hp-step"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 16, padding: 32, transition: 'border-color 0.3s, transform 0.2s' }}
            >
              <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 40, height: 40, borderRadius: 10, background: C.greenGlow, border: '1px solid rgba(52, 211, 153, 0.2)', color: C.green, fontWeight: 800, fontSize: 16, marginBottom: 20, fontFamily: C.font }}>
                {num}
              </div>
              <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 12, color: C.white, fontFamily: C.font }}>{title}</h3>
              <p style={{ fontSize: 15, color: C.gray300, lineHeight: 1.6, fontFamily: C.font }}>{body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Divider */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 32px' }}>
        <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.06)' }} />
      </div>

      {/* ================================================================ */}
      {/* SECURITY TIERS */}
      {/* ================================================================ */}
      <section style={{ maxWidth: 1200, margin: '0 auto', padding: '100px 32px' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: C.greenGlow, border: '1px solid rgba(52, 211, 153, 0.2)', color: C.green, padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 24, fontFamily: C.font }}>
          &#128274; Security Model
        </div>
        <h2 style={{ fontSize: 40, fontWeight: 800, lineHeight: 1.15, letterSpacing: '-1px', marginBottom: 16, color: C.white, fontFamily: C.font }}>
          Four layers. Zero phishing.
        </h2>
        <p style={{ fontSize: 18, color: C.gray300, maxWidth: 600, marginBottom: 64, lineHeight: 1.7, fontFamily: C.font }}>
          Progressive security that starts at zero friction and escalates to hardware-level unphishable authentication. All layers activate automatically.
        </p>

        <div
          className="hp-tiers"
          style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20 }}
        >
          {[
            { icon: '&#128273;', bg: 'rgba(59, 130, 246, 0.15)', title: 'Cryptographic Signing', desc: 'Every QR code is signed with ECDSA-P256. Unregistered fakes are instantly detected.', tag: 'Automatic', tagStyle: { background: 'rgba(52, 211, 153, 0.1)', color: C.green } },
            { icon: '&#127912;', bg: 'rgba(168, 85, 247, 0.15)', title: 'Visual Proof', desc: 'Server-generated ephemeral image with location, device, and timestamp. Cannot be cloned.', tag: 'Automatic', tagStyle: { background: 'rgba(52, 211, 153, 0.1)', color: C.green } },
            { icon: '&#128737;', bg: 'rgba(245, 158, 11, 0.15)', title: 'Anti-Proxy Detection', desc: 'TLS fingerprinting, latency analysis, and canvas hashing detect real-time MitM proxying.', tag: 'Automatic', tagStyle: { background: 'rgba(52, 211, 153, 0.1)', color: C.green } },
            { icon: '&#128274;', bg: 'rgba(52, 211, 153, 0.15)', title: 'WebAuthn Passkeys', desc: 'Hardware-backed, origin-bound authentication. Physically impossible to phish.', tag: 'One-time setup', tagStyle: { background: 'rgba(59, 130, 246, 0.1)', color: C.blueAccent } },
          ].map(({ icon, bg, title, desc, tag, tagStyle }) => (
            <div
              key={title}
              className="hp-tier"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 16, padding: 28, position: 'relative', overflow: 'hidden', transition: 'border-color 0.3s, transform 0.2s' }}
            >
              <div
                style={{ width: 48, height: 48, borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22, marginBottom: 16, background: bg }}
                dangerouslySetInnerHTML={{ __html: icon }}
              />
              <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 8, color: C.white, fontFamily: C.font }}>{title}</h3>
              <p style={{ fontSize: 13, color: C.gray300, lineHeight: 1.5, fontFamily: C.font }}>{desc}</p>
              <span style={{ marginTop: 16, display: 'inline-block', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, padding: '4px 10px', borderRadius: 6, fontFamily: C.font, ...tagStyle }}>
                {tag}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* Divider */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 32px' }}>
        <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.06)' }} />
      </div>

      {/* ================================================================ */}
      {/* FEATURES */}
      {/* ================================================================ */}
      <section style={{ maxWidth: 1200, margin: '0 auto', padding: '100px 32px' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: C.greenGlow, border: '1px solid rgba(52, 211, 153, 0.2)', color: C.green, padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 24, fontFamily: C.font }}>
          &#9889; Platform
        </div>
        <h2 style={{ fontSize: 40, fontWeight: 800, lineHeight: 1.15, letterSpacing: '-1px', marginBottom: 16, color: C.white, fontFamily: C.font }}>
          Built for developers. Scaled for enterprise.
        </h2>
        <p style={{ fontSize: 18, color: C.gray300, maxWidth: 600, marginBottom: 64, lineHeight: 1.7, fontFamily: C.font }}>
          Everything you need to secure physical QR codes, from prototype to millions of daily verifications.
        </p>

        <div
          className="hp-features-grid"
          style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 24 }}
        >
          {[
            { icon: '&#128230;', title: 'SDKs for Every Platform', desc: 'First-class SDKs for Node.js, Python, Go, PHP, Swift, and Kotlin. Consistent API across all languages.' },
            { icon: '&#127760;', title: 'Global Edge Verification', desc: 'Verification endpoint on Cloudflare Workers. Sub-50ms response time worldwide. Always on.' },
            { icon: '&#128205;', title: 'Geospatial Binding', desc: 'QR codes bound to GPS coordinates. Verification page confirms the scanner is at the registered location.' },
            { icon: '&#128276;', title: 'Webhooks & Events', desc: 'Every scan, verification, and fraud detection fires a webhook. Build automated workflows on every event.' },
            { icon: '&#127981;', title: 'Multi-Tenant Isolation', desc: 'Each customer gets isolated keys, branding, user pools, and analytics. Enterprise-grade from day one.' },
            { icon: '&#128202;', title: 'Fraud Intelligence', desc: 'ML-powered anomaly detection. Real-time alerts when fraudulent QR codes appear at your locations.' },
            { icon: '&#128196;', title: 'Transparency Log', desc: 'Public, append-only audit trail of every issued QR code. Auditable by anyone, trusted by institutions.' },
            { icon: '&#127912;', title: 'Custom Branding', desc: 'White-label verification pages with your logo, colors, and copy. Your brand, our security infrastructure.' },
            { icon: '&#128272;', title: 'Compliance Ready', desc: 'SOC 2, GDPR, and ISO 27001 on the roadmap. EU data residency. Built for regulated industries.' },
          ].map(({ icon, title, desc }) => (
            <div
              key={title}
              className="hp-feature"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 16, padding: 28, transition: 'border-color 0.3s' }}
            >
              <div
                style={{ fontSize: 28, marginBottom: 16 }}
                dangerouslySetInnerHTML={{ __html: icon }}
              />
              <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 8, color: C.white, fontFamily: C.font }}>{title}</h3>
              <p style={{ fontSize: 14, color: C.gray300, lineHeight: 1.6, fontFamily: C.font }}>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Divider */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 32px' }}>
        <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.06)' }} />
      </div>

      {/* ================================================================ */}
      {/* OPEN PROTOCOL */}
      {/* ================================================================ */}
      <section style={{ maxWidth: 1200, margin: '0 auto', padding: '100px 32px' }}>
        <div
          className="hp-protocol-grid"
          style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 64, alignItems: 'center' }}
        >
          {/* Left: content */}
          <div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(59, 130, 246, 0.1)', border: '1px solid rgba(59, 130, 246, 0.2)', color: C.blueGlow, padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 24, fontFamily: C.font }}>
              &#128218; Open Standard
            </div>
            <h2 style={{ fontSize: 36, fontWeight: 800, lineHeight: 1.15, letterSpacing: '-1px', marginBottom: 20, color: C.white, fontFamily: C.font }}>
              Built on an open protocol. QRVA.
            </h2>
            <p style={{ fontSize: 17, color: C.gray300, lineHeight: 1.7, marginBottom: 16, fontFamily: C.font }}>
              Auth0 won by building on OAuth and OIDC. QRAuth builds on QRVA — an open specification for signing and verifying physical QR codes that anyone can implement.
            </p>
            <p style={{ fontSize: 17, color: C.gray300, lineHeight: 1.7, marginBottom: 16, fontFamily: C.font }}>
              The protocol is freely licensed. QRAuth is the reference implementation with the best developer experience, trust registry, and network effects.
            </p>
            <ul style={{ listStyle: 'none', marginTop: 24, padding: 0 }}>
              {[
                'ECDSA-P256 signing with compact 64-byte signatures',
                'Geospatial binding with WGS84 coordinates',
                'Merkle tree transparency log (RFC 6962 compatible)',
                'Standardized event schema for interoperability',
                'Compliance test suite for third-party implementations',
              ].map((item) => (
                <li key={item} style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 14, fontSize: 15, color: C.gray200, fontFamily: C.font }}>
                  <span style={{ color: C.green, fontWeight: 700, flexShrink: 0, marginTop: 2 }}>&#10003;</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>

          {/* Right: protocol code block */}
          <div style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 16, overflow: 'hidden', boxShadow: '0 25px 60px rgba(0,0,0,0.4)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '14px 20px', background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#EF4444', display: 'inline-block' }} />
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#F59E0B', display: 'inline-block' }} />
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#22C55E', display: 'inline-block' }} />
              <span style={{ marginLeft: 12, fontFamily: C.mono, fontSize: 12, color: C.gray400 }}>PROTOCOL.md</span>
            </div>
            <div
              style={{ padding: 24, fontFamily: C.mono, fontSize: 13, lineHeight: 1.8, overflowX: 'auto' }}
              dangerouslySetInnerHTML={{ __html: `<span style="color:#64748B">## QRVA Protocol v1.0</span>
<br><br>
<span style="color:#64748B">### QR Payload Format</span>
<br><span style="color:#34D399">https://[verifier]/v/[token]</span>
<br><br>
<span style="color:#64748B">### Signing</span>
<br><span style="color:#93C5FD">algorithm</span>: <span style="color:#67E8F9">ECDSA-P256</span>
<br><span style="color:#93C5FD">hash</span>:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#67E8F9">SHA-256</span>
<br><span style="color:#93C5FD">signature</span>: <span style="color:#F59E0B">64 bytes</span> (compact)
<br><br>
<span style="color:#64748B">### Verification Flow</span>
<br><span style="color:#F59E0B">1.</span> Token resolution
<br><span style="color:#F59E0B">2.</span> Signature verification
<br><span style="color:#F59E0B">3.</span> Geospatial check
<br><span style="color:#F59E0B">4.</span> Trust score computation
<br><br>
<span style="color:#64748B">### Event Types</span>
<br><span style="color:#34D399">qr.created</span> | <span style="color:#34D399">qr.scanned</span>
<br><span style="color:#34D399">qr.verified</span> | <span style="color:#34D399">fraud.detected</span>
<br><span style="color:#34D399">passkey.enrolled</span> | <span style="color:#34D399">passkey.verified</span>` }}
            />
          </div>
        </div>
      </section>

      {/* Divider */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 32px' }}>
        <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.06)' }} />
      </div>

      {/* ================================================================ */}
      {/* CTA */}
      {/* ================================================================ */}
      <section style={{ maxWidth: 800, margin: '0 auto', padding: '100px 32px', textAlign: 'center' }}>
        <h2
          className="hp-cta-h2"
          style={{ fontSize: 44, fontWeight: 800, lineHeight: 1.15, letterSpacing: '-1.5px', marginBottom: 20, color: C.white, fontFamily: C.font }}
        >
          Start verifying QR codes<br />in five minutes
        </h2>
        <p style={{ fontSize: 18, color: C.gray300, marginBottom: 40, lineHeight: 1.7, fontFamily: C.font }}>
          Free tier includes 1,000 verifications/month and 100 QR codes.<br />
          No credit card required.
        </p>
        <div style={{ display: 'flex', justifyContent: 'center', gap: 16, flexWrap: 'wrap', marginBottom: 32 }}>
          <RouterLink
            href={paths.auth.jwt.signUp}
            className="hp-btn-primary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: C.green, color: C.navy, padding: '14px 28px', borderRadius: 10, fontSize: 16, fontWeight: 700, textDecoration: 'none', transition: 'all 0.2s', fontFamily: C.font }}
          >
            Create Free Account &rarr;
          </RouterLink>
          <a
            href="#"
            className="hp-btn-secondary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'transparent', color: C.gray200, padding: '14px 28px', borderRadius: 10, fontSize: 16, fontWeight: 600, textDecoration: 'none', border: '1px solid rgba(255,255,255,0.15)', transition: 'all 0.2s', fontFamily: C.font }}
          >
            Read the Docs
          </a>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 10, padding: '14px 24px', fontFamily: C.mono, fontSize: 15, color: C.green }}>
          $ npm install @qrauth/node
        </div>
      </section>

      {/* ================================================================ */}
      {/* FOOTER */}
      {/* ================================================================ */}
      <footer style={{ maxWidth: 1200, margin: '0 auto', padding: '60px 32px', borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 24 }}>
        <div style={{ fontSize: 14, color: C.gray400, fontFamily: C.font }}>
          &copy; 2026 QRAuth. The authentication layer for physical QR codes.
        </div>
        <ul style={{ display: 'flex', gap: 28, listStyle: 'none', padding: 0, margin: 0 }}>
          {['Docs', 'GitHub', 'Status', 'Privacy', 'Terms'].map((label) => (
            <li key={label}>
              <a
                href="#"
                className="hp-footer-link"
                style={{ fontSize: 14, color: C.gray400, textDecoration: 'none', transition: 'color 0.2s', fontFamily: C.font }}
              >
                {label}
              </a>
            </li>
          ))}
        </ul>
      </footer>
    </Box>
  );
}
