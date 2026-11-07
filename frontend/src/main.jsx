import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { ToastProvider, ConfirmHost } from "./ui";
import "./styles.css";

async function boot() {
  if (import.meta.env.VITE_DEMO === "1") (await import("./mock.js")).installMock();
  createRoot(document.getElementById("root")).render(
    <ToastProvider>
      <App />
      <ConfirmHost />
    </ToastProvider>
  );
}
boot();
