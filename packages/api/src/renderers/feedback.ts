import { esc } from './utils.js';
import type { RenderContext } from './index.js';

function renderFeedbackContent(ctx: RenderContext): string {
  const c = ctx.qrCode.content as any;
  if (!c) return '<p>No feedback form.</p>';

  return `
    <style>
      .fb-title { font-size: 22px; font-weight: 800; color: #1B2A4A; text-align: center; margin-bottom: 8px; }
      .fb-desc { font-size: 14px; color: #637381; text-align: center; margin-bottom: 24px; line-height: 1.6; }
      .fb-stars { display: flex; justify-content: center; gap: 8px; margin-bottom: 20px; }
      .fb-star { font-size: 36px; cursor: pointer; color: #dfe3e8; transition: color 0.2s; }
      .fb-star.active, .fb-star:hover { color: #FFAB00; }
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
        ${[1, 2, 3, 4, 5].map(n => `<span class="fb-star" data-rating="${n}" onclick="setRating(${n})">&#9733;</span>`).join('')}
      </div>

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
        // For now, just show thanks (API endpoint for submission is Phase 3)
        document.getElementById('fb-form').style.display = 'none';
        document.getElementById('fb-thanks').style.display = 'block';
      }
    </script>
  `;
}

export default renderFeedbackContent;
