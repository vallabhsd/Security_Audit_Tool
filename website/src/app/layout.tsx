import type { Metadata } from 'next';
import './globals.css';
import { colors } from '@/lib/colors';
import { ThemeProvider } from '@/components/theme-provider';

export const metadata: Metadata = {
  title: 'WebSecurityAudit - Website Security Audit Tools',
  description:
    'Secure your website with our advanced security audit scripts and tools. Identify vulnerabilities, prevent attacks, and keep your website safe.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="scroll-smooth" suppressHydrationWarning>
      <head>
        <style>
          {`
            :root {
              --radius: 0.625rem;
              
              /* Background & Foreground */
              --background: ${colors.background.light};
              --foreground: ${colors.text.light};
              
              /* Card */
              --card: ${colors.background.light};
              --card-foreground: ${colors.text.light};
              
              /* Popover */
              --popover: ${colors.background.light};
              --popover-foreground: ${colors.text.light};
              
              /* Primary */
              --primary: ${colors.primary.DEFAULT};
              --primary-foreground: oklch(0.98 0 0);
              
              /* Secondary */
              --secondary: ${colors.secondary.DEFAULT};
              --secondary-foreground: oklch(0.98 0 0);
              
              /* Muted */
              --muted: oklch(0.96 0 0);
              --muted-foreground: oklch(0.4 0 0);
              
              /* Accent */
              --accent: ${colors.accent.DEFAULT};
              --accent-foreground: oklch(0.98 0 0);
              
              /* Destructive */
              --destructive: ${colors.danger.DEFAULT};
              --destructive-foreground: oklch(0.98 0 0);
              
              /* Border and Input */
              --border: oklch(0.85 0 0);
              --input: oklch(0.85 0 0);
              --ring: ${colors.primary.light};
            }
            
            .dark {
              --background: ${colors.background.dark};
              --foreground: ${colors.text.dark};
              
              --card: oklch(0.2 0 0);
              --card-foreground: ${colors.text.dark};
              
              --popover: oklch(0.2 0 0);
              --popover-foreground: ${colors.text.dark};
              
              --primary: ${colors.primary.light};
              --primary-foreground: oklch(0.1 0 0);
              
              --secondary: ${colors.secondary.light};
              --secondary-foreground: oklch(0.1 0 0);
              
              --muted: oklch(0.15 0 0);
              --muted-foreground: oklch(0.7 0 0);
              
              --accent: ${colors.accent.light};
              --accent-foreground: oklch(0.1 0 0);
              
              --destructive: ${colors.danger.DEFAULT};
              --destructive-foreground: oklch(0.98 0 0);
              
              --border: oklch(0.3 0 0);
              --input: oklch(0.3 0 0);
              --ring: ${colors.primary.DEFAULT};
            }
          `}
        </style>
      </head>
      <body className="antialiased">
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
