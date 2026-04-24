// src/tools/executor.js
// Safely execute shell commands with timeout, output capture, and error handling

import { spawn } from "child_process";

export async function execTool(cmd, args = [], opts = {}) {
  const { timeout = 300, env = {}, cwd } = opts;
  const timeoutMs = timeout * 1000;

  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let killed = false;

    const proc = spawn(cmd, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (stdout.length > 512_000) {
        stdout = stdout.slice(0, 512_000) + "\n\n[OUTPUT TRUNCATED - exceeded 500KB]";
        proc.kill("SIGTERM");
        killed = true;
      }
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      if (stderr.length > 128_000) {
        stderr = stderr.slice(0, 128_000) + "\n[STDERR TRUNCATED]";
      }
    });

    const timer = setTimeout(() => {
      killed = true;
      proc.kill("SIGTERM");
      setTimeout(() => {
        try { proc.kill("SIGKILL"); } catch {}
      }, 5000);
    }, timeoutMs);

    proc.on("close", (code) => {
      clearTimeout(timer);
      let output = "";
      if (killed) output += `Process timed out after ${timeout}s or output was truncated.\n\n`;
      if (stdout.trim()) output += stdout.trim();
      if (stderr.trim()) output += `\n\n--- STDERR ---\n${stderr.trim()}`;
      if (!output.trim()) output = `Process exited with code ${code} (no output)`;
      resolve({ content: [{ type: "text", text: output }] });
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      resolve({
        content: [{
          type: "text",
          text: `Failed to execute "${cmd}": ${err.message}\n\nMake sure the tool is installed in the container.`,
        }],
      });
    });
  });
}
