'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import { Menu, X, Shield, ChevronDown } from 'lucide-react';
import { ThemeToggle } from '@/components/theme-toggle';

export function Header() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);

  // Handle scroll event to change navbar appearance
  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 10);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const toggleDropdown = (name: string) => {
    setActiveDropdown(activeDropdown === name ? null : name);
  };

  return (
    <header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled
          ? 'bg-background/90 backdrop-blur-md shadow-sm border-b border-border'
          : 'bg-transparent'
      }`}
    >
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16 md:h-20">
          {/* Logo */}
          <motion.div
            className="flex items-center"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
          >
            <Link href="/" className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-primary" />
              <span className="font-bold text-xl">WebSecurityAudit</span>
            </Link>
          </motion.div>

          {/* Desktop Navigation */}
          <motion.nav
            className="hidden md:flex space-x-8"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <Link
              href="/"
              className="text-foreground hover:text-primary transition-colors"
            >
              Home
            </Link>

            <div className="relative group">
              <button
                className="flex items-center text-foreground hover:text-primary transition-colors"
                onClick={() => toggleDropdown('services')}
              >
                Services
                <ChevronDown className="ml-1 h-4 w-4" />
              </button>

              <div className="absolute left-0 mt-2 w-48 rounded-md shadow-lg bg-card border border-border overflow-hidden transform origin-top scale-95 opacity-0 group-hover:scale-100 group-hover:opacity-100 transition-all duration-200">
                <div className="py-1">
                  <Link
                    href="/services/vulnerability-scanning"
                    className="block px-4 py-2 text-sm hover:bg-accent hover:text-accent-foreground transition-colors"
                  >
                    Vulnerability Scanning
                  </Link>
                  <Link
                    href="/services/penetration-testing"
                    className="block px-4 py-2 text-sm hover:bg-accent hover:text-accent-foreground transition-colors"
                  >
                    Penetration Testing
                  </Link>
                  <Link
                    href="/services/security-assessment"
                    className="block px-4 py-2 text-sm hover:bg-accent hover:text-accent-foreground transition-colors"
                  >
                    Security Assessment
                  </Link>
                  <Link
                    href="/services/compliance-auditing"
                    className="block px-4 py-2 text-sm hover:bg-accent hover:text-accent-foreground transition-colors"
                  >
                    Compliance Auditing
                  </Link>
                </div>
              </div>
            </div>

            <Link
              href="/about"
              className="text-foreground hover:text-primary transition-colors"
            >
              About
            </Link>

            <Link
              href="/blog"
              className="text-foreground hover:text-primary transition-colors"
            >
              Blog
            </Link>

            <Link
              href="/contact"
              className="text-foreground hover:text-primary transition-colors"
            >
              Contact
            </Link>
          </motion.nav>

          {/* CTA Button and Theme Toggle */}
          <motion.div
            className="hidden md:flex items-center space-x-2"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <ThemeToggle />
            <Link
              href="/get-started"
              className="inline-flex h-10 items-center justify-center rounded-md bg-primary px-6 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              Get Started
            </Link>
          </motion.div>

          {/* Mobile Menu Button and Theme Toggle */}
          <div className="md:hidden flex items-center space-x-1">
            <ThemeToggle />
            <button
              onClick={toggleMobileMenu}
              className="text-foreground p-2 rounded-md hover:bg-primary/10 transition-colors"
              aria-label={isMobileMenuOpen ? 'Close Menu' : 'Open Menu'}
            >
              {isMobileMenuOpen ? (
                <X className="h-6 w-6" />
              ) : (
                <Menu className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div
            className="md:hidden bg-background border-t border-border"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
          >
            <div className="container mx-auto px-4 py-4 space-y-1">
              <Link
                href="/"
                className="block py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Home
              </Link>

              <div>
                <button
                  className="flex items-center justify-between w-full py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                  onClick={() => toggleDropdown('mobileServices')}
                >
                  <span>Services</span>
                  <ChevronDown
                    className={`h-4 w-4 transition-transform ${
                      activeDropdown === 'mobileServices' ? 'rotate-180' : ''
                    }`}
                  />
                </button>

                {activeDropdown === 'mobileServices' && (
                  <div className="pl-4 mt-1 border-l-2 border-border ml-3 space-y-1">
                    <Link
                      href="/services/vulnerability-scanning"
                      className="block py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                      onClick={() => setIsMobileMenuOpen(false)}
                    >
                      Vulnerability Scanning
                    </Link>
                    <Link
                      href="/services/penetration-testing"
                      className="block py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                      onClick={() => setIsMobileMenuOpen(false)}
                    >
                      Penetration Testing
                    </Link>
                    <Link
                      href="/services/security-assessment"
                      className="block py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                      onClick={() => setIsMobileMenuOpen(false)}
                    >
                      Security Assessment
                    </Link>
                    <Link
                      href="/services/compliance-auditing"
                      className="block py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                      onClick={() => setIsMobileMenuOpen(false)}
                    >
                      Compliance Auditing
                    </Link>
                  </div>
                )}
              </div>

              <Link
                href="/about"
                className="block py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                About
              </Link>

              <Link
                href="/blog"
                className="block py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Blog
              </Link>

              <Link
                href="/contact"
                className="block py-2 px-3 rounded-md hover:bg-primary/10 transition-colors"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Contact
              </Link>

              <div className="pt-4">
                <Link
                  href="/get-started"
                  className="block w-full text-center py-2 rounded-md bg-primary text-primary-foreground shadow hover:bg-primary/90 transition-colors"
                  onClick={() => setIsMobileMenuOpen(false)}
                >
                  Get Started
                </Link>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
