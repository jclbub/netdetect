import React from "react";
import Footer from "./components/Footer";
import { Cobe } from "./components/Cobe";
import TypingEffect from "./components/TypingEffect";
import Navbar from "./components/Navbar";

function Home() {
	return (
		<>
			<Navbar />

			<section
				id="home"
				className="home flex flex-col-reverse md:flex-row items-center h-screen px-6 md:px-[10%] py-[5%] bg-gradient-to-br from-blue-200 via-white to-blue-100 relative overflow-hidden"
			>
				{/* Column 1 */}
				<div className="column1 flex flex-col items-center md:items-start justify-center h-full w-full md:w-[50%] space-y-6 text-center md:text-left">
					<h1 className="text-[2.5rem] md:text-[5.5rem] font-extrabold text-gray-800 leading-tight md:leading-[5.5rem] mb-4 tracking-tight">
						Protect your <br />
						<TypingEffect />
					</h1>
					<p className="text-sm md:text-lg text-gray-600 mt-2 max-w-md leading-relaxed">
						Easy network management with AI analysis and user monitoring to
						secure your infrastructure.
					</p>
					<button className="bg-gradient-to-r from-blue-500 to-blue-700 text-white py-2 px-6 md:py-3 md:px-8 rounded-2xl shadow-lg transform hover:scale-105 transition duration-300 ease-in-out hover:shadow-xl animate-shine">
						Getting Started
					</button>
				</div>

				{/* Column 2 */}
				<div className="column2 relative h-full w-full md:w-[50%] flex items-center justify-center">
					<Cobe />
					<div className="select-none absolute bottom-0 right-0 mb-4 md:mb-8 mr-2 md:mr-4 text-right text-sm md:text-[1rem] text-gray-600">
						Secure all networks in all places
					</div>
					<div className="absolute top-1/3 md:top-1/4 right-1/3 md:right-1/4 w-[150px] md:w-[300px] h-[150px] md:h-[300px] bg-blue-200 rounded-full opacity-40 blur-xl animate-pulse"></div>
				</div>
			</section>

			<Footer />
		</>
	);
}

export default Home;
