import { esc } from './utils.js';
import type { RenderContext } from './index.js';

function renderFeedbackContent(ctx: RenderContext): string {
  const c = ctx.qrCode.content as any;
  if (!c) return '<p>No feedback form.</p>';

  const collectName = c.collectName === true || c.collectName === 'true';
  const collectEmail = c.collectEmail === true || c.collectEmail === 'true';
  const collectPhone = c.collectPhone === true || c.collectPhone === 'true';

  return `
    <style>
      .fb-title { font-size: 22px; font-weight: 800; color: #1B2A4A; text-align: center; margin-bottom: 8px; }
      .fb-desc { font-size: 14px; color: #637381; text-align: center; margin-bottom: 24px; line-height: 1.6; }
      .fb-stars { display: flex; justify-content: center; gap: 8px; margin-bottom: 20px; }
      .fb-star { font-size: 36px; cursor: pointer; color: #dfe3e8; transition: color 0.2s; user-select: none; }
      .fb-star.active, .fb-star:hover { color: #FFAB00; }
      .fb-input { width: 100%; padding: 10px 14px; border: 1px solid #dfe3e8; border-radius: 8px; font-size: 14px; font-family: inherit; box-sizing: border-box; margin-bottom: 10px; }
      .fb-input:focus { outline: none; border-color: #00A76F; }
      .fb-textarea { width: 100%; padding: 12px; border: 1px solid #dfe3e8; border-radius: 8px; font-size: 14px; font-family: inherit; resize: vertical; min-height: 80px; box-sizing: border-box; }
      .fb-textarea:focus { outline: none; border-color: #00A76F; }
      .fb-submit { display: block; width: 100%; padding: 14px; margin-top: 16px; background: #00A76F; color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; }
      .fb-submit:hover { background: #007B55; }
      .fb-submit:disabled { background: #919eab; cursor: not-allowed; }
      .fb-thanks { text-align: center; padding: 24px; display: none; }
      .fb-thanks h3 { color: #00A76F; margin-bottom: 8px; }
    </style>

    <div id="fb-form">
      <div class="fb-title">${esc(c.title || 'How was your experience?')}</div>
      ${c.description ? `<div class="fb-desc">${esc(c.description)}</div>` : ''}

      <div class="fb-stars" id="fb-stars">
        ${[1,2,3,4,5].map(n => `<span class="fb-star" data-rating="${n}" onclick="setRating(${n})">&#9733;</span>`).join('')}
      </div>

      ${collectName ? '<input class="fb-input" id="fb-name" placeholder="Your name" />' : ''}
      ${collectEmail ? '<input class="fb-input" id="fb-email" type="email" placeholder="Your email" />' : ''}
      ${collectPhone ? '<input class="fb-input" id="fb-phone" type="tel" placeholder="Your phone" />' : ''}

      <textarea class="fb-textarea" id="fb-comment" placeholder="Leave a comment (optional)..."></textarea>

      <button class="fb-submit" id="fb-submit" onclick="submitFeedback()" disabled>Submit Feedback</button>
    </div>

    <div class="fb-thanks" id="fb-thanks">
      <div style="font-size:48px;margin-bottom:12px;">&#10003;</div>
      <h3>${esc(c.thanksMessage || 'Thank you for your feedback!')}</h3>
      <p style="color:#637381;font-size:14px;">Your response has been recorded.</p>
    </div>

    <script>
      var selectedRating = 0;
      function setRating(n) {
        selectedRating = n;
        document.querySelectorAll('.fb-star').forEach(function(s, i) {
          s.className = 'fb-star' + (i < n ? ' active' : '');
        });
        document.getElementById('fb-submit').disabled = false;
      }
      function submitFeedback() {
        var btn = document.getElementById('fb-submit');
        btn.disabled = true;
        btn.textContent = 'Submitting...';
        var comment = document.getElementById('fb-comment').value;
        var nameEl = document.getElementById('fb-name');
        var emailEl = document.getElementById('fb-email');
        var phoneEl = document.getElementById('fb-phone');
        var payload = { rating: selectedRating };
        if (comment) payload.comment = comment;
        if (nameEl && nameEl.value) payload.name = nameEl.value;
        if (emailEl && emailEl.value) payload.email = emailEl.value;
        if (phoneEl && phoneEl.value) payload.phone = phoneEl.value;
        fetch(window.location.pathname + '/feedback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        })
        .then(function() {
          document.getElementById('fb-form').style.display = 'none';
          document.getElementById('fb-thanks').style.display = 'block';
        })
        .catch(function() {
          btn.disabled = false;
          btn.textContent = 'Submit Feedback';
          alert('Failed to submit. Please try again.');
        });
      }
    </script>
  `;
}

export default renderFeedbackContent;
