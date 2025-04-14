'use client';

import React from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { Github, Twitter, Linkedin, Mail } from 'lucide-react';

export function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-muted/20 border-t border-border py-12">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="col-span-1 md:col-span-1">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              viewport={{ once: true }}
            >
              <h3 className="text-lg font-bold mb-4">WebSecurityAudit</h3>
              <p className="text-muted-foreground mb-4">
                Protecting websites with advanced security audit scripting.
              </p>
              <div className="flex space-x-4">
                <motion.a
                  href="https://github.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-primary transition-colors"
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Github className="h-5 w-5" />
                  <span className="sr-only">GitHub</span>
                </motion.a>
                <motion.a
                  href="https://twitter.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-primary transition-colors"
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Twitter className="h-5 w-5" />
                  <span className="sr-only">Twitter</span>
                </motion.a>
                <motion.a
                  href="https://linkedin.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-primary transition-colors"
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Linkedin className="h-5 w-5" />
                  <span className="sr-only">LinkedIn</span>
                </motion.a>
              </div>
            </motion.div>
          </div>

          <div className="col-span-1">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 }}
              viewport={{ once: true }}
            >
              <h3 className="text-lg font-bold mb-4">Quick Links</h3>
              <ul className="space-y-2">
                <li>
                  <Link
                    href="/about"
                    className="text-muted-foreground hover:text-primary transition-colors"
                  >
                    About Us
                  </Link>
                </li>
                <li>
                  <Link
                    href="/services"
                    className="text-muted-foreground hover:text-primary transition-colors"
                  >
                    Services
                  </Link>
                </li>
                <li>
                  <Link
                    href="/blog"
                    className="text-muted-foreground hover:text-primary transition-colors"
                  >
                    Blog
                  </Link>
                </li>
                <li>
                  <Link
                    href="/contact"
                    className="text-muted-foreground hover:text-primary transition-colors"
                  >
                    Contact
                  </Link>
                </li>
              </ul>
            </motion.div>
          </div>

          <div className="col-span-1">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              viewport={{ once: true }}
            >
              <h3 className="text-lg font-bold mb-4">Services</h3>
              <ul className="space-y-2">
                <li>
                  <Link
                    href="/services/vulnerability-scanning"
                    className="text-muted-foreground hover:text-primary transition-colors"
                  >
                    Vulnerability Scanning
                  </Link>
                </li>
                <li>
                  <Link
                    href="/services/penetration-testing"
                    className="text-muted-foreground hover:text-primary transition-colors"
                  >
                    Penetration Testing
                  </Link>
                </li>
                <li>
                  <Link
                    href="/services/security-assessment"
                    className="text-muted-foreground hover:text-primary transition-colors"
                  >
                    Security Assessment
                  </Link>
                </li>
                <li>
                  <Link
                    href="/services/compliance-auditing"
                    className="text-muted-foreground hover:text-primary transition-colors"
                  >
                    Compliance Auditing
                  </Link>
                </li>
              </ul>
            </motion.div>
          </div>

          <div className="col-span-1">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              viewport={{ once: true }}
            >
              <h3 className="text-lg font-bold mb-4">Contact Us</h3>
              <address className="not-italic">
                <p className="text-muted-foreground mb-2">
                  123 Security Street
                </p>
                <p className="text-muted-foreground mb-2">Web City, WS 12345</p>
                <p className="text-muted-foreground mb-4">United States</p>
                <p className="flex items-center text-muted-foreground hover:text-primary transition-colors">
                  <Mail className="h-4 w-4 mr-2" />
                  <a href="mailto:info@websecurityaudit.com">
                    info@websecurityaudit.com
                  </a>
                </p>
              </address>
            </motion.div>
          </div>
        </div>

        <div className="mt-12 pt-8 border-t border-border">
          <p className="text-center text-muted-foreground text-sm">
            © {currentYear} WebSecurityAudit. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}
