import { useState, useEffect } from "react";

export function NetworkScanner() {
	const [scannedData, setScannedData] = useState([]);
	const [loading, setLoading] = useState(true);

	const VITE_wsUrl = import.meta.env.VITE_wsUrl;

	useEffect(() => {
		const socket = new WebSocket(`${VITE_wsUrl}/ws/network-scanner/`);

		socket.onopen = () => {
			console.log("WebSocket connection established.");
			setLoading(false);
		};

		socket.onmessage = (event) => {
			try {
				const data = JSON.parse(event.data);
				setScannedData(data.data || data);
				console.log("scanned data received:", data);
			} catch (err) {
				console.error("Error parsing WebSocket message:", err);
			}
		};

		socket.onerror = (error) => {
			console.error("WebSocket error:", error);
			setLoading(false);
		};

		socket.onclose = () => {
			console.log("WebSocket connection closed.");
		};

		return () => {
			socket.close();
		};
	}, [VITE_wsUrl]);

	return { scannedData, loading };
}
