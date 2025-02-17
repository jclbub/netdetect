import React, { useEffect } from "react";
import Sidebar from "./components/sidebar";
import { NetworkScanner } from "./networkData/networkscanner";

function NetWorkDashboard() {
	const { scannedData, loading } = NetworkScanner();

	useEffect(() => {
		console.log("Scanned Data:", scannedData); // Debugging the traffic data
	}, [scannedData]);

	return (
		<div className="bg-white min-h-screen">
			<Sidebar />
			<div className="p-4 ml-20">
				<h1 className="text-2xl font-bold mb-4">Network Dashboard</h1>
				{loading ? (
					<p>Loading...</p>
				) : (
					<div className="overflow-x-auto">
						<table className="min-w-full border-collapse border border-gray-300 text-left">
							<thead className="bg-gray-100">
								<tr>
									<th className="px-4 py-2 border border-gray-300">Hostname</th>
									<th className="px-4 py-2 border border-gray-300">
										IP Address
									</th>
									<th className="px-4 py-2 border border-gray-300">
										Danger Level
									</th>
									<th className="px-4 py-2 border border-gray-300">State</th>
								</tr>
							</thead>
							<tbody>
								{scannedData.map((scanned_reults, index) => (
									<tr
										key={index}
										className={index % 2 === 0 ? "bg-gray-50" : "bg-white"}
									>
										<td className="px-4 py-2 border border-gray-300">
											{scanned_reults.hostname}
										</td>
										<td className="px-4 py-2 border border-gray-300">
											{scanned_reults.host}
										</td>
										<td className="px-4 py-2 border border-gray-300">
											{scanned_reults.danger_level}
										</td>
										<td className="px-4 py-2 border border-gray-300">
											{scanned_reults.state}
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

export default NetWorkDashboard;
