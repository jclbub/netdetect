import React, { useEffect } from "react";
import Sidebar from "./components/sidebar";
import { useTrafficData } from "./networkData/trafficDashboard";
import { NetworkScanner } from "./networkData/networkscanner";

function DashboardHome() {
	const { trafficData, loading } = useTrafficData();
	const { scannedData } = NetworkScanner();

	useEffect(() => {
		console.log("Traffic Data:", trafficData); // Debugging the traffic data
		console.log("Scanned Data:", scannedData); // Debugging the traffic data
	}, [trafficData, scannedData]);

	return (
		<div className="bg-white min-h-screen">
			<Sidebar />
			<div className="p-4 ml-20">
				<h1 className="text-2xl font-bold mb-4">Traffic Dashboard</h1>
				{loading ? (
					<p>Loading...</p>
				) : (
					<div className="overflow-x-auto">
						<table className="min-w-full border-collapse border border-gray-300 text-left">
							<thead className="bg-gray-100">
								<tr>
									<th className="px-4 py-2 border border-gray-300">Hostname</th>
									<th className="px-4 py-2 border border-gray-300">
										Device Type
									</th>
									<th className="px-4 py-2 border border-gray-300">
										IP Address
									</th>
									<th className="px-4 py-2 border border-gray-300">
										Total Bytes
									</th>
									<th className="px-4 py-2 border border-gray-300">Mbps</th>
								</tr>
							</thead>
							<tbody>
								{trafficData.map((data, index) => (
									<tr
										key={index}
										className={index % 2 === 0 ? "bg-gray-50" : "bg-white"}
									>
										<td className="px-4 py-2 border border-gray-300">
											{data.hostname}
										</td>
										<td className="px-4 py-2 border border-gray-300">
											{data.deviceType}
										</td>
										<td className="px-4 py-2 border border-gray-300">
											{data.ip}
										</td>
										<td className="px-4 py-2 border border-gray-300">
											{data.totalBytes}
										</td>
										<td className="px-4 py-2 border border-gray-300">
											{data.mbps}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</div>
		</div>
	);
}

export default DashboardHome;
