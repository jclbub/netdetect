import React, { useState } from "react";
import { FaBars, FaThLarge, FaPowerOff, FaChartLine } from "react-icons/fa";
import { Link, useNavigate } from "react-router-dom";

function Sidebar() {
	const [isSidebarOpen, setIsSidebarOpen] = useState(false);
	const navigate = useNavigate();

	const handleLogout = () => {
		localStorage.removeItem("accessToken");
		localStorage.removeItem("refreshToken");
		navigate("/");
	};

	const toggleSidebar = () => {
		setIsSidebarOpen(!isSidebarOpen);
	};

	return (
		<>
			<aside
				id="default-sidebar"
				className={`fixed top-0 left-0 z-40 h-screen transition-transform ${
					isSidebarOpen ? "w-50" : "w-16"
				} transition-duration-150ms sm:translate-x-0`}
				aria-label="Sidebar"
			>
				<div className="h-full px-3 py-4 overflow-y-auto bg-gray-50 dark:bg-gray-800">
					<ul className="space-y-2 font-medium">
						<li>
							<button
								onClick={toggleSidebar}
								className="flex items-center p-2 text-gray-900 rounded-lg dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700 group"
							>
								<FaBars className="w-6 h-6 text-white" />
							</button>
						</li>

						<li>
							<Link
								to="/"
								className="flex items-center p-2 text-gray-900 rounded-lg dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700 group"
							>
								<FaThLarge className="w-6 h-6 text-white" />
								<span className={`${!isSidebarOpen ? "hidden" : ""} ms-3`}>
									Traffic Dashboard
								</span>
							</Link>
						</li>

						<li>
							<Link
								to="networkDashboard"
								className="flex items-center p-2 text-gray-900 rounded-lg dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700 group"
							>
								<FaChartLine className="w-6 h-6 text-white" />
								<span className={`${!isSidebarOpen ? "hidden" : ""} ms-3`}>
									Network Dashboard
								</span>
							</Link>
						</li>

						{/* Add more sidebar links here */}
						<li>
							<button
								onClick={handleLogout}
								className="flex items-center p-2 text-gray-900 rounded-lg dark:text-white hover:bg-gray-100 dark:hover:bg-gray-700 group"
							>
								<FaPowerOff className="w-6 h-6 text-white" />

								<span className={`${!isSidebarOpen ? "hidden" : ""} ms-3`}>
									Logout
								</span>
							</button>
						</li>
					</ul>
				</div>
			</aside>
		</>
	);
}

export default Sidebar;
