import { useState, useEffect } from "react";
import {
	BrowserRouter as Router,
	Route,
	Routes,
	Navigate,
} from "react-router-dom";
import "./Styles/index.css";
import Home from "./pages/index/Home";
import About from "./pages/index/About";
import Contact from "./pages/index/Contact";
import DashboardHome from "./pages/dashboard/DashboardHome";
import NetWorkDashboard from "./pages/dashboard/NetworkDashboard";
import { useAuth } from "../hooks/useauth,jsx";

function App() {
	const { isLoggedIn, loading } = useAuth();

	if (loading) {
		// Show a loading indicator while checking authentication state
		return <div>Loading...</div>;
	}
	return (
		<Router>
			<Routes>
				{/* {isLoggedIn ? ( */}
				<>
					<Route path="/" element={<DashboardHome />} />
					<Route path="/networkDashboard" element={<NetWorkDashboard />} />
				</>
				{/* ) : (
					<>
						<Route path="/" element={<Home />} />
						<Route path="/about" element={<About />} />
						<Route path="/contact" element={<Contact />} />
					</>
				)} */}
			</Routes>
		</Router>
	);
}

export default App;
