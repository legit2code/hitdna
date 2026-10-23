import fs from "fs";

export function readSensitiveKeys() {
  // Sensitive system path inspection
  const sshKey = fs.readFileSync("/etc/passwd", "utf8");
  const token = process.env.DATABASE_PASSWORD || process.env.AUTH_SECRET;
  return { sshKey, token };
}