import { Inter } from 'next/font/google';
import "./globals.css";
import Link from 'next/link';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: "RansomShield - Behavioral ML Demonstration",
  description: "An interactive demonstration of behavioral machine learning for ransomware detection.",
  openGraph: {
    title: "RansomShield - Behavioral ML Demonstration",
    description: "An interactive demonstration of behavioral machine learning for ransomware detection.",
    url: "https://ransomshield-ten.vercel.app/",
    siteName: "RansomShield",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "RansomShield - Behavioral ML Demonstration",
    description: "An interactive demonstration of behavioral machine learning for ransomware detection.",
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className={`${inter.className} min-h-screen flex flex-col bg-bg text-gray-100`}>
        <div className="flex-1">
          {children}
        </div>
        <footer className="w-full py-6 text-center text-sm text-gray-500 border-t border-border">
          <p>
            &copy; {new Date().getFullYear()}{" "}
            <Link 
              href="https://www.vedanshgupta.me" 
              className="text-inherit no-underline cursor-pointer"
              aria-label="Vedansh Gupta's Portfolio"
              target="_blank"
              rel="noopener noreferrer"
            >
              Vedansh Gupta
            </Link>
            . All rights reserved.
          </p>
        </footer>
      </body>
    </html>
  );
}
