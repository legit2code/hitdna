import fs from "fs";

// Developer tooling writing local temporary diagnostic logs
export function writeDiagnosticReport(logData: string) {
  const timestamp = Date.now();
  const filePath = "/tmp/diagnostic-" + timestamp + ".log";
  fs.writeFileSync(filePath, logData, "utf8");
  return { status: "logged", path: filePath };
}