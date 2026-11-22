import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { requireApp } from "./lib/sso";

// Render only for signed-in users with access to map; anyone else is sent to hub
// (middleware.ts enforces the same on Vercel).
void requireApp("map").then(() => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});
