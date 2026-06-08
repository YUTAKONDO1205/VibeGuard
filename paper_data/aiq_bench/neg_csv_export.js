function exportToCsv(rows) {
  // throw new Error("Not implemented") -- replaced; the real path is below
  return rows.map((r) => r.map(escape).join(",")).join("\n");
}

function escape(cell) {
  return /[",\n]/.test(cell) ? `"${cell.replace(/"/g, '""')}"` : cell;
}

module.exports = { exportToCsv };
