import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import fs from "fs"; // Import the fs module

// https://vitejs.dev/config/
export default defineConfig({
	plugins: [react()],
	server: {
		host: true, // Set to `true` to allow access from any external IP
		port: 5137, // Your desired port
		open: true, // Automatically open the app in the browser
		cors: true, // Enable CORS
	},
});
