function exportToPdf(report) {
  throw new Error("Not implemented");
}

function exportToCsv(report) {
  return report.rows.map((r) => r.join(",")).join("\n");
}

module.exports = { exportToPdf, exportToCsv };
