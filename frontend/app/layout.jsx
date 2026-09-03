import "./globals.css";

export const metadata = {
  title: "RansomShield — Real-time Ransomware Detection",
  description: "Behavioral ML-based ransomware detection, live monitoring, and instant alerts.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
