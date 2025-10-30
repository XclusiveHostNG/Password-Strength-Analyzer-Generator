(function () {
  const dataElement = document.getElementById('strength-data');
  if (!dataElement) {
    return;
  }

  const entropy = Number(dataElement.dataset.entropy || 0);
  const score = Number(dataElement.dataset.score || 0);
  const length = Number(dataElement.dataset.length || 0);
  const charSpace = Number(dataElement.dataset.charSpace || 0);

  const strengthCtx = document.getElementById('strengthChart');
  const entropyCtx = document.getElementById('entropyChart');

  if (strengthCtx) {
    new Chart(strengthCtx, {
      type: 'doughnut',
      data: {
        labels: ['Score', 'Remaining'],
        datasets: [
          {
            data: [score, Math.max(0, 100 - score)],
            backgroundColor: ['#198754', '#d1e7dd'],
            borderWidth: 0,
          },
        ],
      },
      options: {
        plugins: {
          legend: { position: 'bottom' },
          tooltip: {
            callbacks: {
              label: function (context) {
                if (context.dataIndex === 0) {
                  return `Strength score: ${score}`;
                }
                return `Potential improvement: ${100 - score}`;
              },
            },
          },
        },
      },
    });
  }

  if (entropyCtx) {
    const recommendedEntropy = Math.max(80, entropy + 10);
    new Chart(entropyCtx, {
      type: 'bar',
      data: {
        labels: ['Current Entropy', 'Target (80 bits)'],
        datasets: [
          {
            label: 'Entropy (bits)',
            data: [entropy, 80],
            backgroundColor: ['#0d6efd', '#6c757d'],
          },
        ],
      },
      options: {
        indexAxis: 'y',
        scales: {
          x: {
            beginAtZero: true,
            suggestedMax: recommendedEntropy,
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (context) {
                return `${context.parsed.x.toFixed(2)} bits`;
              },
            },
          },
        },
      },
    });
  }
})();
