'use strict';

const selectedReviewIds = () => [...document.querySelectorAll('.review-select:checked')].map(item => item.value);

function updateReviewSelection() {
  const boxes = [...document.querySelectorAll('.review-select')];
  const selected = boxes.filter(item => item.checked).length;
  const selectAll = document.querySelector('#reviewSelectAll');
  document.querySelector('#reviewSelectedCount').textContent = String(selected);
  selectAll.checked = boxes.length > 0 && selected === boxes.length;
  selectAll.indeterminate = selected > 0 && selected < boxes.length;
}

function enhanceReviewRows() {
  document.querySelectorAll('#reviewRows tr').forEach(row => {
    if (row.querySelector('.review-select') || row.querySelector('.empty')) return;
    const action = row.querySelector('[data-review]');
    if (!action) return;
    const id = action.dataset.review;
    const cell = document.createElement('td');
    cell.className = 'select-cell';
    cell.innerHTML = `<input class="review-select" type="checkbox" value="${esc(id)}" aria-label="选择该研判事件">`;
    row.prepend(cell);
    if (!row.querySelector('[data-op="claim"]')) {
      const claim = document.createElement('button');
      claim.className = 'secondary';
      claim.dataset.review = id;
      claim.dataset.op = 'claim';
      claim.textContent = '认领';
      row.querySelector('.row-actions').prepend(claim);
    }
  });
  const emptyCell = document.querySelector('#reviewRows .empty');
  if (emptyCell) emptyCell.colSpan = 9;
  updateReviewSelection();
}

async function batchReview(operation) {
  if (!requireToken()) return;
  const ids = selectedReviewIds();
  if (!ids.length) {
    show('请先选择需要处理的研判事件', true);
    return;
  }
  const labels = {claim: '认领', approve: '批准及处置', reject: '拒绝'};
  const reason = prompt(`请输入批量${labels[operation]}原因（共 ${ids.length} 项）：`);
  if (!reason) return;
  let succeeded = 0;
  const failures = [];
  for (const id of ids) {
    try {
      await api(`/api/v1/reviews/${encodeURIComponent(id)}/${operation}`, {
        method: 'POST', body: JSON.stringify({reason})
      });
      succeeded += 1;
    } catch (error) {
      failures.push(id);
    }
  }
  await loadReviews();
  show(failures.length ? `已处理 ${succeeded} 项，失败 ${failures.length} 项` : `已批量${labels[operation]} ${succeeded} 项`, failures.length > 0);
}

document.querySelector('#reviewSelectAll').addEventListener('change', event => {
  document.querySelectorAll('.review-select').forEach(item => { item.checked = event.target.checked; });
  updateReviewSelection();
});
document.querySelector('#reviewRows').addEventListener('change', event => {
  if (event.target.matches('.review-select')) updateReviewSelection();
});
document.addEventListener('click', event => {
  const button = event.target.closest('[data-batch-review]');
  if (button) batchReview(button.dataset.batchReview).catch(error => show(error.message, true));
});
new MutationObserver(enhanceReviewRows).observe(document.querySelector('#reviewRows'), {childList: true});

document.querySelector('#blackPanel thead tr').innerHTML =
  '<th>IP</th><th>方向</th><th>备注</th><th>状态</th><th>有效期</th><th>加入时间</th><th>命中</th><th>来源</th><th>操作</th>';
document.querySelector('#whitePanel thead tr').innerHTML =
  '<th>IP / 网段</th><th>方向</th><th>备注</th><th>状态</th><th>有效期</th><th>加入时间</th><th>命中</th><th>来源</th><th>操作</th>';

const reviewHeaderCells = document.querySelectorAll('#reviews thead th');
reviewHeaderCells[1].textContent = '攻击源 IP';
const locationHeader = document.createElement('th');
locationHeader.textContent = '源地址归属地';
const targetHeader = document.createElement('th');
targetHeader.textContent = '攻击目标';
reviewHeaderCells[1].after(locationHeader, targetHeader);
