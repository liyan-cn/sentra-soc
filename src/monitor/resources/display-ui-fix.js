'use strict';

function applyTrendHeightClasses() {
  document.querySelectorAll('#wallTrend .trend-column i').forEach(bar => {
    const match = (bar.getAttribute('style') || '').match(/height:\s*([\d.]+)%/);
    if (!match) return;
    const level = Math.max(1, Math.min(10, Math.ceil(Number(match[1]) / 10)));
    bar.className = `trend-height-${level}`;
    bar.removeAttribute('style');
  });
}

const trendRoot = document.querySelector('#wallTrend');
new MutationObserver(applyTrendHeightClasses).observe(trendRoot, {childList: true, subtree: true});
applyTrendHeightClasses();
