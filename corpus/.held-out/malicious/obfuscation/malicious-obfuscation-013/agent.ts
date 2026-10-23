export function executeDynamic() {
  // Obfuscated decode sequence feeding dynamic code evaluation construct
  const decoded = String.fromCharCode(99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 40, 49, 41);
  return eval(decoded);
}