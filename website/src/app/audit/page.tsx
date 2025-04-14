'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Toaster } from '@/components/ui/sonner';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  ArrowRight,
  Globe,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Lock,
  XCircle,
} from 'lucide-react';

function AuditPage() {
  const [url, setUrl] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [urlError, setUrlError] = useState('');

  const validateUrl = (input: string) => {
    // Reset error state
    setUrlError('');

    // Check if URL is empty
    if (!input.trim()) {
      setUrlError('Please enter a URL');
      return false;
    }

    // Basic URL pattern with protocol requirement
    const urlPattern =
      /^(https?:\/\/)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/[a-zA-Z0-9-._~:/?#[\]@!$&'()*+,;=]*)?$/;

    if (!urlPattern.test(input)) {
      setUrlError('Please enter a valid URL (e.g., https://example.com)');
      return false;
    }

    // Ensure protocol is present, add https:// if missing
    if (!/^https?:\/\//i.test(input)) {
      setUrl('https://' + input);
    }

    return true;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    // Validate URL before proceeding
    if (!validateUrl(url)) {
      toast.error('Invalid URL', {
        description: urlError || 'Please enter a valid website URL',
      });
      return;
    }

    setIsSubmitting(true);
    // Simulate form submission - we'll replace this with actual logic later
    setTimeout(() => {
      setIsSubmitting(false);
      toast.success('Security scan initiated', {
        description: 'Redirecting to results dashboard...',
      });
      // Redirect to dashboard after successful submission
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 1500);
    }, 2000);
  };

  // Handle URL change with validation feedback
  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const inputValue = e.target.value;
    setUrl(inputValue);

    // Clear error when user starts typing again
    if (urlError) {
      setUrlError('');
    }
  };

  return (
    <main className="min-h-screen flex flex-col">
      <Toaster position="top-center" />
      <Header />

      <div className="flex-1 pt-24 pb-16">
        <div className="container mx-auto px-4">
          {/* Hero Section */}
          <motion.div
            className="max-w-4xl mx-auto text-center mb-12"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <Badge variant="secondary" className="mb-4 px-3 py-1 text-sm">
              Website Security Audit
            </Badge>
            <h1 className="text-4xl md:text-5xl font-bold mb-4">
              Check Your Website's{' '}
              <span className="text-primary">Security</span>
            </h1>
            <p className="text-xl text-muted-foreground">
              Enter your website URL below and we'll analyze its security
              posture with our advanced scanning tools.
            </p>
          </motion.div>

          {/* URL Input Form */}
          <motion.div
            className="max-w-3xl mx-auto"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="bg-card border border-border rounded-xl shadow-lg overflow-hidden">
              <div className="p-8">
                <form onSubmit={handleSubmit} className="space-y-8">
                  <div className="space-y-4">
                    <label
                      htmlFor="website-url"
                      className="block text-lg font-medium"
                    >
                      Website URL
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                        <Globe className="h-5 w-5 text-muted-foreground" />
                      </div>
                      <input
                        id="website-url"
                        type="text"
                        value={url}
                        onChange={handleUrlChange}
                        placeholder="https://example.com"
                        required
                        className={`flex h-14 w-full rounded-md border ${
                          urlError
                            ? 'border-destructive focus-visible:ring-destructive/20'
                            : 'border-input'
                        } bg-background pl-10 pr-4 py-2 text-base ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50`}
                        aria-invalid={!!urlError}
                        aria-describedby={urlError ? 'url-error' : undefined}
                      />
                      {urlError && (
                        <div className="absolute inset-y-0 right-0 flex items-center pr-3">
                          <XCircle className="h-5 w-5 text-destructive" />
                        </div>
                      )}
                    </div>
                    {urlError ? (
                      <p id="url-error" className="text-sm text-destructive">
                        {urlError}
                      </p>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        We'll scan your website for security vulnerabilities and
                        provide a detailed report.
                      </p>
                    )}
                  </div>

                  <div className="flex justify-center">
                    <motion.div
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      <Button
                        type="submit"
                        className="h-12 px-8 text-base font-medium"
                        disabled={isSubmitting}
                      >
                        {isSubmitting ? (
                          <>
                            <div className="animate-spin mr-2">⏳</div>
                            Scanning...
                          </>
                        ) : (
                          <>
                            Start Security Scan
                            <ArrowRight className="ml-2 h-4 w-4" />
                          </>
                        )}
                      </Button>
                    </motion.div>
                  </div>
                </form>
              </div>
            </div>
          </motion.div>

          {/* Security Features */}
          <motion.div
            className="max-w-5xl mx-auto mt-20"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <h2 className="text-2xl md:text-3xl font-bold text-center mb-12">
              Our Comprehensive{' '}
              <span className="text-primary">Security Checks</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {/* SSL/TLS Check */}
              <motion.div
                className="bg-card border border-border rounded-lg p-6 shadow-sm hover:shadow-md transition-all duration-300"
                whileHover={{ y: -5 }}
              >
                <div className="rounded-full bg-primary/10 p-3 w-fit mb-4">
                  <Lock className="h-6 w-6 text-primary" />
                </div>
                <h3 className="text-xl font-bold mb-2">SSL/TLS Certificate</h3>
                <p className="text-muted-foreground">
                  We check your site's SSL certificate, protocol versions, and
                  encryption strength.
                </p>
              </motion.div>

              {/* Security Headers */}
              <motion.div
                className="bg-card border border-border rounded-lg p-6 shadow-sm hover:shadow-md transition-all duration-300"
                whileHover={{ y: -5 }}
              >
                <div className="rounded-full bg-secondary/10 p-3 w-fit mb-4">
                  <Shield className="h-6 w-6 text-secondary" />
                </div>
                <h3 className="text-xl font-bold mb-2">Security Headers</h3>
                <p className="text-muted-foreground">
                  Verify implementation of essential security headers to protect
                  against common attacks.
                </p>
              </motion.div>

              {/* Malware Detection */}
              <motion.div
                className="bg-card border border-border rounded-lg p-6 shadow-sm hover:shadow-md transition-all duration-300"
                whileHover={{ y: -5 }}
              >
                <div className="rounded-full bg-accent/10 p-3 w-fit mb-4">
                  <AlertTriangle className="h-6 w-6 text-accent" />
                </div>
                <h3 className="text-xl font-bold mb-2">Malware Detection</h3>
                <p className="text-muted-foreground">
                  Check if your website is flagged for malware or appears on
                  security blacklists.
                </p>
              </motion.div>

              {/* CMS Vulnerabilities */}
              <motion.div
                className="bg-card border border-border rounded-lg p-6 shadow-sm hover:shadow-md transition-all duration-300"
                whileHover={{ y: -5 }}
              >
                <div className="rounded-full bg-primary/10 p-3 w-fit mb-4">
                  <CheckCircle2 className="h-6 w-6 text-primary" />
                </div>
                <h3 className="text-xl font-bold mb-2">CMS Checks</h3>
                <p className="text-muted-foreground">
                  Identify your CMS platform and check for outdated versions and
                  known vulnerabilities.
                </p>
              </motion.div>

              {/* Open Ports */}
              <motion.div
                className="bg-card border border-border rounded-lg p-6 shadow-sm hover:shadow-md transition-all duration-300"
                whileHover={{ y: -5 }}
              >
                <div className="rounded-full bg-secondary/10 p-3 w-fit mb-4">
                  <Shield className="h-6 w-6 text-secondary" />
                </div>
                <h3 className="text-xl font-bold mb-2">Open Ports</h3>
                <p className="text-muted-foreground">
                  Detect unnecessarily exposed services and ports that could be
                  security risks.
                </p>
              </motion.div>

              {/* WHOIS Information */}
              <motion.div
                className="bg-card border border-border rounded-lg p-6 shadow-sm hover:shadow-md transition-all duration-300"
                whileHover={{ y: -5 }}
              >
                <div className="rounded-full bg-accent/10 p-3 w-fit mb-4">
                  <Globe className="h-6 w-6 text-accent" />
                </div>
                <h3 className="text-xl font-bold mb-2">Domain Security</h3>
                <p className="text-muted-foreground">
                  Analyze WHOIS information and DNS configuration for potential
                  security issues.
                </p>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </div>

      <Footer />
    </main>
  );
}

export default AuditPage;
