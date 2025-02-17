module.exports = {
	content: [
		"./src/**/*.{html,js,jsx,ts,tsx}", // Adjust according to your project files
	],
	theme: {
		extend: {},
	},
	plugins: [
		require("daisyui"), // Ensure this line is present
	],
};
